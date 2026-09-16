rule StealC_cystack_b8ed4e31
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_b8ed4e31"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Current User:" ascii
        $key_2 = "Installed Apps:" ascii
        $key_3 = "Network Info:" ascii
        $key_4 = "Process List:" ascii
        $key_5 = "System Summary:" ascii

    condition:
        all of ($key_*)
}