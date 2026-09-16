rule venom_20170125 : malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects Venom samples - 20170125"
                
    strings:
        $venom_00 = "justCANTbeSTOPPED"
        $venom_01 = "%%VENOM%AUTHENTICATE%%"
        $venom_02 = "%%VENOM%OK%OK%%"


    condition:
                uint32be(0) == 0x7f454c46 and

                all of ($venom_*)
}