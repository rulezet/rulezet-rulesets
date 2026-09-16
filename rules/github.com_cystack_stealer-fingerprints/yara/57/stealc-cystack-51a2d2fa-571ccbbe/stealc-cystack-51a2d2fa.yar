rule StealC_cystack_51a2d2fa
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_51a2d2fa"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Color Depth:" ascii
        $key_2 = "Device Name:" ascii
        $key_3 = "Device String:" ascii
        $key_4 = "Imperator:" ascii
        $key_5 = "Installed Apps:" ascii
        $key_6 = "Network Info:" ascii
        $key_7 = "Process List:" ascii
        $key_8 = "Process count:" ascii
        $key_9 = "Resolution:" ascii
        $key_10 = "System Summary:" ascii

    condition:
        all of ($key_*)
}