rule StealC_cystack_0092c07b
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_0092c07b"

    strings:
        $key_0 = "All Users:" ascii
        $key_1 = "Color Depth:" ascii
        $key_2 = "Current User:" ascii
        $key_3 = "Device Name:" ascii
        $key_4 = "Device String:" ascii
        $key_5 = "Installed Apps:" ascii
        $key_6 = "MTA:" ascii
        $key_7 = "Network Info:" ascii
        $key_8 = "Process List:" ascii
        $key_9 = "Process count:" ascii
        $key_10 = "Resolution:" ascii
        $key_11 = "System Summary:" ascii

    condition:
        all of ($key_*)
}