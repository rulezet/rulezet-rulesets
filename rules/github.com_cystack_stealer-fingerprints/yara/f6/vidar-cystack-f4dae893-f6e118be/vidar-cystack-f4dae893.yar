rule Vidar_cystack_f4dae893
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f4dae893"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "GUID:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Ip:" ascii
        $key_6 = "MachineID:" ascii
        $key_7 = "Processor:" ascii
        $key_8 = "RAM:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "Version:" ascii
        $key_11 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}