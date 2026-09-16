rule PXA_Stealer_cystack_b7ba88f7
{
    meta:
        family = "PXA Stealer"
        fingerprint_id = "cystack_b7ba88f7"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Data Information:" ascii
        $key_3 = "Username:" ascii

    condition:
        all of ($key_*)
}