rule PXA_Stealer_cystack_51cd69b2
{
    meta:
        family = "PXA Stealer"
        fingerprint_id = "cystack_51cd69b2"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Data Information:" ascii
        $key_2 = "Username:" ascii

    condition:
        all of ($key_*)
}