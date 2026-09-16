rule StealC_cystack_b7b299ef
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_b7b299ef"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Current User:" ascii
        $key_2 = "Installed Apps:" ascii
        $key_3 = "Process List:" ascii
        $key_4 = "Process count:" ascii
        $key_5 = "System Summary:" ascii

    condition:
        all of ($key_*)
}