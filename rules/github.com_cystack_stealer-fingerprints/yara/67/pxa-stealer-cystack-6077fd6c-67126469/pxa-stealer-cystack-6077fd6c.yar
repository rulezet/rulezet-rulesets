rule PXA_Stealer_cystack_6077fd6c
{
    meta:
        family = "PXA Stealer"
        fingerprint_id = "cystack_6077fd6c"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Data Information:" ascii
        $key_2 = "IP:" ascii
        $key_3 = "User:" ascii

    condition:
        all of ($key_*)
}