rule StealC_cystack_7a8ccb6e
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_7a8ccb6e"

    strings:
        $key_0 = "Network Info:" ascii
        $key_1 = "Process List:" ascii
        $key_2 = "Process count:" ascii
        $key_3 = "System Summary:" ascii

    condition:
        all of ($key_*)
}