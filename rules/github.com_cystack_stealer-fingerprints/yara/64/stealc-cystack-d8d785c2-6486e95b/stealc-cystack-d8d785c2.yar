rule StealC_cystack_d8d785c2
{
    meta:
        family = "StealC"
        fingerprint_id = "cystack_d8d785c2"

    strings:
        $key_0 = "Color Depth:" ascii
        $key_1 = "Device Name:" ascii
        $key_2 = "Device String:" ascii
        $key_3 = "Network Info:" ascii
        $key_4 = "Process List:" ascii
        $key_5 = "Process count:" ascii
        $key_6 = "Resolution:" ascii
        $key_7 = "System Summary:" ascii

    condition:
        all of ($key_*)
}