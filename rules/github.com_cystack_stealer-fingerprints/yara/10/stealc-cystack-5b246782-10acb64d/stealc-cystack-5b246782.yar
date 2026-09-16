rule StealC_cystack_5b246782
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_5b246782"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Color Depth:" ascii
        $key_2 = "Device Name:" ascii
        $key_3 = "Device String:" ascii
        $key_4 = "Installed Apps:" ascii
        $key_5 = "Microsoft Age of Empires II:" ascii
        $key_6 = "Network Info:" ascii
        $key_7 = "Process List:" ascii
        $key_8 = "Process count:" ascii
        $key_9 = "Resolution:" ascii
        $key_10 = "System Summary:" ascii

    condition:
        all of ($key_*)
}