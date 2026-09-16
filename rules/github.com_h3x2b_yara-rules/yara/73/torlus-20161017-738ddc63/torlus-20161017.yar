rule torlus_20161017: malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects Torlus/LizKebab/GayFgt/Bashdoor samples - 20161017"
                                                                                                        
    strings:
        $cmd_00 = "PING"
        $cmd_01 = "GETLOCALIP"
        $cmd_02 = "SCANNER"
        $cmd_03 = "HOLD"
        $cmd_04 = "JUNK"
        $cmd_05 = "UDP"
        $cmd_06 = "COMBO"
        $cmd_07 = "TCP"
        $cmd_08 = "KILLATTK"
        $cmd_09 = "LOLNOGTFO"
        $cmd_10 = "GTFOFAG"
        $cmd_11 = "FATCOCK"

        $ua_01 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $ua_02 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $ua_03 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1"
        $ua_04 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)"
        $ua_05 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
        $ua_06 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
        $ua_07 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
        $ua_08 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1"
        $ua_09 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)"
        $ua_10 = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)"
        $ua_11 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
        $ua_12 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"

        $msg_01 = "ogin:"
        $msg_02 = "assword:"
        $msg_03 = "ncorrect"
        $msg_04 = "HTTP"
        $msg_05 = "REPORT %s:%s:%s"
        $msg_06 = "Failed opening raw socket."
        $msg_07 = "Failed setting raw headers mode."
        $msg_08 = "Invalid flag \"%s\""
        $msg_09 = "My IP: %s"
        $msg_10 = "BUILD %s"
        $msg_11 = "BOGOMIPS"
        $msg_12 = "/proc/cpuinfo"

        $shell_01 = "rm -rf /var/log/wtmp"
        $shell_02 = "rm -rf /tmp/*"
        $shell_03 = "history -c"
        $shell_04 = "rm -rf ~/.bash_history"
        $shell_05 = "rm -rf /bin/netstat"
        $shell_06 = "service iptables stop"

    condition:
                uint32be(0) == 0x7f454c46 and

                8 of ($cmd_*) and

                5 of ($ua_*) and

                6 of ($msg_*) and

                3 of ($shell_*)

}