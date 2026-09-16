rule PCInfo_Stealer_cystack_47382a1a
{
    meta:
        family = "PCInfo Stealer"
        fingerprint_id = "cystack_47382a1a"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "HWID:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "MAC:" ascii
        $key_5 = "PC Name:" ascii
        $key_6 = "PC Username:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "Resolution:" ascii

    condition:
        all of ($key_*)
}