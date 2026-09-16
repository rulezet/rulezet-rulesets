rule StealC_cystack_1f8e4d74
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_1f8e4d74"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Installed Apps:" ascii
        $key_2 = "Network Info:" ascii
        $key_3 = "System Summary:" ascii

    condition:
        all of ($key_*)
}