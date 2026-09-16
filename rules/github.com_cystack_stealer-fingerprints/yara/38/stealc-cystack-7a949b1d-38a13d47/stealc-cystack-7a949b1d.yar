rule StealC_cystack_7a949b1d
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_7a949b1d"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Installed Apps:" ascii
        $key_2 = "Network Info:" ascii
        $key_3 = "Process List:" ascii
        $key_4 = "Process count:" ascii
        $key_5 = "System Summary:" ascii

    condition:
        all of ($key_*)
}