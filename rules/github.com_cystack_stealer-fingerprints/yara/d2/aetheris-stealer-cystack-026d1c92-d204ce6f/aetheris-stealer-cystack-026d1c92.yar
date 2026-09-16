rule Aetheris_Stealer_cystack_026d1c92
{
    meta:
        family = "Aetheris Stealer"
        fingerprint_id = "cystack_026d1c92"

    strings:
        $key_0 = "Clipboard:" ascii
        $key_1 = "Hwid:" ascii
        $key_2 = "Input ISO:" ascii
        $key_3 = "Machine:" ascii
        $key_4 = "Now:" ascii
        $key_5 = "User:" ascii

    condition:
        all of ($key_*)
}