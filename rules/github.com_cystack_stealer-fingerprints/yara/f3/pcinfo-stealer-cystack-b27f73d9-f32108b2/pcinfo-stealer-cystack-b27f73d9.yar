rule PCInfo_Stealer_cystack_b27f73d9
{
    meta:
        family = "PCInfo Stealer"
        fingerprint_id = "cystack_b27f73d9"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "HWID:" ascii
        $key_2 = "IP:" ascii
        $key_3 = "MAC:" ascii
        $key_4 = "PC Name:" ascii
        $key_5 = "PC Username:" ascii
        $key_6 = "RAM:" ascii
        $key_7 = "Resolution:" ascii

    condition:
        all of ($key_*)
}