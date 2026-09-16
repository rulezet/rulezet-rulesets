rule StealC_cystack_11aa8cef
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_11aa8cef"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Installed Apps:" ascii
        $key_2 = "Process List:" ascii
        $key_3 = "Process count:" ascii

    condition:
        all of ($key_*)
}