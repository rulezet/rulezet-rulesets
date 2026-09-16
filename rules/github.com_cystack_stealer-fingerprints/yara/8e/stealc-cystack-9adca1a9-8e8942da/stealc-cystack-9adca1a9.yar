rule StealC_cystack_9adca1a9
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_9adca1a9"

    strings:
        $key_0 = "Color Depth:" ascii
        $key_1 = "Device Name:" ascii
        $key_2 = "Device String:" ascii
        $key_3 = "Installed Apps:" ascii
        $key_4 = "Network Info:" ascii
        $key_5 = "Process List:" ascii
        $key_6 = "Process count:" ascii
        $key_7 = "Resolution:" ascii
        $key_8 = "System Summary:" ascii

    condition:
        all of ($key_*)
}