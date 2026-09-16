rule StealC_cystack_2f4aa4ef
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_2f4aa4ef"

    strings:
        $key_0 = "Current User:" ascii
        $key_1 = "Network Info:" ascii
        $key_2 = "Process List:" ascii
        $key_3 = "Process count:" ascii
        $key_4 = "System Summary:" ascii

    condition:
        all of ($key_*)
}