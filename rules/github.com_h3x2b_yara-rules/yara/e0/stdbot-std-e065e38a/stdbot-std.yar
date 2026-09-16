rule stdbot_std : malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects STDbot samples - 20161009"
                                        
    strings:
        $irc_00 = "CONNECT"
        $irc_01 = "NICK"
        $irc_02 = "PING"
        $irc_03 = "JOIN"

        $std_00 = ":>bot +std"
        $std_01 = "PRIVMSG"
        $std_02 = "[STD]Hitting"


    condition:
                uint32be(0) == 0x7f454c46 and

                all of ($irc_*) and

                all of ($std_*)
}