rule PXA_Stealer_cystack_94cdfe2d
{
    meta:
        family = "PXA Stealer"
        fingerprint_id = "cystack_94cdfe2d"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Data Information:" ascii
        $key_2 = "IP:" ascii
        $key_3 = "Username:" ascii

    condition:
        all of ($key_*)
}