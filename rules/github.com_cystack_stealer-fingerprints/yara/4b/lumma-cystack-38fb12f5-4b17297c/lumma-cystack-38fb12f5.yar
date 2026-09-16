rule Lumma_cystack_38fb12f5
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_38fb12f5"

    strings:
        $key_0 = "Configuration:" ascii
        $key_1 = "TG:" ascii

    condition:
        all of ($key_*)
}