rule mirai_20161004 : malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects Mirai samples - 20161004"
                                
    strings:
        $mirai_00 = "/dev/null"
        $mirai_01 = "LCOGQGPTGP"


    condition:
                uint32be(0) == 0x7f454c46 and

                all of ($mirai_*)
}