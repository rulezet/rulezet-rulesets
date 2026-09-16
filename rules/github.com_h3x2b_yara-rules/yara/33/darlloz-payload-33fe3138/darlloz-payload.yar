rule darlloz__payload: malware linux worm
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects darlloz samples - 20161102"
                                
    strings:
        $x_01 = "/var/run/.zollard/"
        $x_02 = "/kernel/net/ipv4/netfilter/ip_tables.ko"
        $x_03 = "/kernel/net/ipv4/netfilter/iptable_filter.ko"
        $x_04 = "telnetd"
        $x_05 = "/var/run/.lightpid"
        $x_06 = "/var/run/.aidrapid"
        $x_07 = "/var/run/lightpid"

    condition:
                uint32be(0) == 0x7f454c46 and

                all of ( $x_* ) 
}