rule stdbot_std2 : malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects STDbot samples - 20161009"
                                                                                                
    strings:
        $std_00 = "shitteru koto dake"
        $std_01 = "nandemo wa shiranai wa yo"


        condition:
                uint32be(0) == 0x7f454c46 and

                all of ($std_*)
}