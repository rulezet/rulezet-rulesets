rule Lumma_cystack_eb33c583
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_eb33c583"

    strings:
        $key_0 = "SN:" ascii
        $key_1 = "Service Tag:" ascii

    condition:
        all of ($key_*)
}