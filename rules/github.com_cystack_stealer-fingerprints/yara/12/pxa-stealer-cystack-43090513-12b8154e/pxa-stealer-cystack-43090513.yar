rule PXA_Stealer_cystack_43090513
{
    meta:
        family = "PXA Stealer"
        fingerprint_id = "cystack_43090513"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "IP:" ascii

    condition:
        all of ($key_*)
}