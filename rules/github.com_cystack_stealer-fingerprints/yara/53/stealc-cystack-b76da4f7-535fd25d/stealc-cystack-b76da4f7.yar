rule StealC_cystack_b76da4f7
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_b76da4f7"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Current User:" ascii
        $key_2 = "Installed Apps:" ascii
        $key_3 = "Network Info:" ascii
        $key_4 = "System Summary:" ascii

    condition:
        all of ($key_*)
}