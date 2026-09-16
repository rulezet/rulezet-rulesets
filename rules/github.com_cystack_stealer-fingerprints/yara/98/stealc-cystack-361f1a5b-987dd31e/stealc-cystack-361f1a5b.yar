rule StealC_cystack_361f1a5b
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_361f1a5b"

    strings:
        $key_0 = "Network Info:" ascii
        $key_1 = "System Summary:" ascii

    condition:
        all of ($key_*)
}