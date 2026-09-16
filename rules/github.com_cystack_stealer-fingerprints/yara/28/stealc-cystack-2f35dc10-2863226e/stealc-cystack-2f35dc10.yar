rule StealC_cystack_2f35dc10
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_2f35dc10"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Installed Apps:" ascii

    condition:
        all of ($key_*)
}