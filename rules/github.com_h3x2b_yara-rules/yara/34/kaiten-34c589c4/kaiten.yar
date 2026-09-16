rule kaiten: malware linux
{
    meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects Kaiten samples - 20161009"
                                                                                                
        strings:
               $kaiten_00 = "NOTICE %s :Kaiten wa goraku"
                $kaiten_01 = "NOTICE %s :TSUNAMI <target> <secs>"
                $kaiten_02 = "NOTICE %s :PAN <target> <port> <secs>"

        condition:
                                uint32be(0) == 0x7f454c46 and

                                2 of ($kaiten_*)
}