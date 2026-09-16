rule coolmemes_linux_dosbot: malware linux
{
    meta:
                description = "Detects unknown linux irc bot - 20161009"
                
    strings:
        $irc_00 = "PING"
        $irc_01 = "PONG!"

        $x_00 = "SCANNER"
        $x_01 = "KILLATTK"
        $x_02 = "COOLMEMES"
        $x_03 = "BOTKILL"
        $x_04 = "HTTPFLOOD"

    condition:
                uint32be(0) == 0x7f454c46 and

                all of ($irc_*) and 

                all of ($x_*)
}