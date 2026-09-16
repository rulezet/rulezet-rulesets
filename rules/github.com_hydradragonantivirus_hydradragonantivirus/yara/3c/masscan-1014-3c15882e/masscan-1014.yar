import "pe"
rule masscan_1014 {
  meta:
    description = "exe - file masscan.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-01-18"
    hash1       = "de903a297afc249bb7d68fef6c885a4c945d740a487fe3e9144a8499a7094131"

  strings:
    $x1  = "User-Agent: masscan/1.0 (https://github.com/robertdavidgraham/masscan)" fullword ascii
    $s2  = "Usage: masscan [Options] -p{Target-Ports} {Target-IP-Ranges}" fullword ascii
    $s3  = "GetProcessAffinityMask() returned error %u" fullword ascii
    $s4  = "Via: HTTP/1.1 ir14.fp.bf1.yahoo.com (YahooTrafficServer/1.2.0.13 [c s f ])" fullword ascii
    $s5  = "C:\\Documents and Settings\\" fullword ascii
    $s6  = "android.com" fullword ascii
    $s7  = "youtube.com" fullword ascii
    $s8  = "espanol.yahoo.com" fullword ascii
    $s9  = "brb.yahoo.com" fullword ascii
    $s10 = "malaysia.yahoo.com" fullword ascii
    $s11 = "att.yahoo.com" fullword ascii
    $s12 = "hsrd.yahoo.com" fullword ascii
    $s13 = "googlecommerce.com" fullword ascii
    $s14 = "maktoob.yahoo.com" fullword ascii
    $s15 = "*.youtube-nocookie.com" fullword ascii
    $s16 = "# TARGET SELECTION (IP, PORTS, EXCLUDES)" fullword ascii
    $s17 = "www.yahoo.com" fullword ascii
    $s18 = "x.509 parser failure: google.com" fullword ascii
    $s19 = "-- forced options: -sS -Pn -n --randomize-hosts -v --send-eth" fullword ascii
    $s20 = "urchin.com" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and
    (pe.imphash() == "9b0b559e373d62a1c93e615f003f8af8" or 10 of them)
}