rule StealC_cystack_5e7036c7
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_5e7036c7"

    strings:
        $key_0 = "Process List:" ascii
        $key_1 = "Process count:" ascii

    condition:
        all of ($key_*)
}