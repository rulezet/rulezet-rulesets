rule torlus_server: malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects Torlus/LizKebab/GayFgt/Bashdoor server samples"
                                        
    strings:
        $cmd_00 = "PING"
        $cmd_01 = "PONG"
        $cmd_02 = "BUILD"
        $cmd_03 = "REPORT"

        $msg_01 = "!* SCANNER ON\n"
        $msg_02 = "!* FATCOCK\n"
        $msg_03 = "buf: \"%s\"\n"
        $msg_04 = "%c]0;Bots connected: %d | Clients connected: %d%c"
        $msg_05 = "WELCOME TO THE BALL PIT"



    condition:
                uint32be(0) == 0x7f454c46 and

                4 of ($cmd_*) and

                2 of ($msg_*)

}