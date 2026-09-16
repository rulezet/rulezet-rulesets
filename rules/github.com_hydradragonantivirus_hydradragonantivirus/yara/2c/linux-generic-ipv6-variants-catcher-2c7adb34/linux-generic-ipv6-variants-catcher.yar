import "elf"
rule linux_generic_ipv6_variants_catcher
{
    meta:
    author      = "@_lubiedo"
    description = "Find IPv6 capable malware for a set of IoT variants"

    strings:
                $t1 = "RANDOMFLOOD"
        $t2 = "RSHELL"
        $t3 = "KEKSERVER"
        $t4 = "GETSPOOFS"
        $t5 = "HACKPKG"
        $t6 = "FUCKIT"
        $t7 = "VERSION"
        $t8 = "KILLALL"
        
                $q1 = "GETLOCALIP"
        $q2 = "SCANNER"
        $q3 = "PONG!"
        $q4 = "PROBING"
        $q5 = "FUCKOFF"

                $s1 = "LOLNOGTFO"
        $s2 = "/proc/net/route"
        $s3 = "admin"
        $s4 = "root"

                $dir1 = "/dev/watchdog"
        $dir2 = "/dev/misc/watchdog"
        $pass1 = "PMMV"
        $pass2 = "FGDCWNV"
        $pass3 = "OMVJGP"
        
                $ipv6_1 = "fe80::" ascii         $ipv6_2 = "2001::" ascii         $ipv6_3 = "2001:41d0:" ascii         $ipv6_4 = "2604:A880:" ascii         $ipv6_5 = "2607:f298:" ascii         
                $ipv6_fmt = "%x:%x:%x:%x:%x:%x:%x:%x"
        
    condition:
        ( elf.type == elf.ET_EXEC and filesize < 1MB ) and (
                        ( $dir1 and $pass1 and $pass2 and not $pass3 and not $dir2 ) or
                        ( all of ($s*) ) or
                        ( 2 of ($q*) ) or
                        ( 2 of ($t*) )
        ) and ( any of ($ipv6_*) or $ipv6_fmt )
}