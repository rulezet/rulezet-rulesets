rule PXA_Stealer_cystack_15c13fbc
{
    meta:
        family = "PXA Stealer"
        fingerprint_id = "cystack_15c13fbc"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Data Information:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "User:" ascii

    condition:
        all of ($key_*)
}