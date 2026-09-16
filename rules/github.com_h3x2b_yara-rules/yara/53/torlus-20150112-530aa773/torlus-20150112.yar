rule torlus_20150112: malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects Torlus/LizKebab/GayFgt/Bashdoor samples - 20150112"
                                        
    strings:
        $cmd_00 = "PING"
        $cmd_01 = "GETLOCALIP"
        $cmd_02 = "SCANNER"
        $cmd_03 = "HOLD"
        $cmd_04 = "JUNK"
        $cmd_05 = "UDP"
        $cmd_06 = "TCP"
        $cmd_07 = "KILLATTK"
        $cmd_08 = "LOLNOGTFO"
        $cmd_09 = "EMAIL"

        $msg_01 = "MAC: %02X:%02X:%02X:%02X:%02X:%02X\n"
        $msg_02 = "Failed to connect...\n"
        $msg_03 = "Link closed by server.\n"
        $msg_04 = "REPORT %s:%s:"
        $msg_05 = "Failed opening raw socket."
        $msg_06 = "Failed setting raw headers mode."
        $msg_07 = "Invalid flag \"%s\""
        $msg_08 = "My IP: %s"
        $msg_09 = "EMAIL <target email> <mx host> <subject no spaces> <message no spaces>"
        $msg_10 = "HOLD <ip> <port> <time>"
        $msg_11 = "HOLD Flooding %s:%d for %d seconds."
        $msg_12 = "JUNK Flooding %s:%d for %d seconds."
        $msg_13 = "UDP Flooding %s for %d seconds."
        $msg_14 = "UDP Flooding %s:%d for %d seconds."
        $msg_15 = "TCP Flooding %s for %d seconds."
        $msg_16 = "Killed %d."
        $msg_17 = "None Killed."
        $msg_18 = "BUILD %s"
        $msg_19 = "BOGOMIPS"
        $msg_20 = "/proc/cpuinfo"

    condition:
                uint32be(0) == 0x7f454c46 and

                8 of ($cmd_*) and

                10 of ($msg_*)

}