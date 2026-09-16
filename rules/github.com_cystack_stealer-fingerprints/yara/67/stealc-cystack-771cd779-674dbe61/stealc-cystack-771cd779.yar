rule StealC_cystack_771cd779
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_771cd779"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Installed Apps:" ascii
        $key_2 = "Network Info:" ascii
        $key_3 = "Process Count:" ascii
        $key_4 = "Process List:" ascii
        $key_5 = "System Summary:" ascii

    condition:
        all of ($key_*)
}