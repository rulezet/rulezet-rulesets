rule StealC_cystack_a9f45237
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_a9f45237"

    strings:
        $key_0 = "Current User:" ascii
        $key_1 = "Network Info:" ascii
        $key_2 = "System Summary:" ascii

    condition:
        all of ($key_*)
}