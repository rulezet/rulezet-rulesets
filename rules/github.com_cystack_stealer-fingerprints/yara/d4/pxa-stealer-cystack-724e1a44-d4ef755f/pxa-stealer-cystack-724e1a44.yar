rule PXA_Stealer_cystack_724e1a44
{
    meta:
        family = "PXA Stealer"
        fingerprint_id = "cystack_724e1a44"

    strings:
        $key_0 = "AntiVirus:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Data Information:" ascii
        $key_3 = "IP:" ascii
        $key_4 = "Username:" ascii

    condition:
        all of ($key_*)
}