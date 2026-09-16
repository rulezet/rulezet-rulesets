rule StealC_cystack_3028b0ca
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_3028b0ca"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Installed Apps:" ascii
        $key_2 = "Process List:" ascii
        $key_3 = "Process count:" ascii
        $key_4 = "System Summary:" ascii

    condition:
        all of ($key_*)
}