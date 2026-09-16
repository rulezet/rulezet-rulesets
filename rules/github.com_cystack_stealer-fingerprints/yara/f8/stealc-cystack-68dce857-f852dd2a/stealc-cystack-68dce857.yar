rule StealC_cystack_68dce857
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_68dce857"

    strings:
        $key_0 = "Process List:" ascii
        $key_1 = "Process count:" ascii
        $key_2 = "System Summary:" ascii

    condition:
        all of ($key_*)
}