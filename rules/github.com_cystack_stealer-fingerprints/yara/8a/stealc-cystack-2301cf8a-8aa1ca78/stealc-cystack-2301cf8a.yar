rule StealC_cystack_2301cf8a
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_2301cf8a"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Color Depth:" ascii
        $key_2 = "Device Name:" ascii
        $key_3 = "Device String:" ascii
        $key_4 = "Installed Apps:" ascii
        $key_5 = "Network Info:" ascii
        $key_6 = "Process List:" ascii
        $key_7 = "Process count:" ascii
        $key_8 = "Resolution:" ascii
        $key_9 = "System Summary:" ascii

    condition:
        all of ($key_*)
}