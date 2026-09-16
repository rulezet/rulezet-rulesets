rule Vidar_cystack_920b9be2
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_920b9be2"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "GUID:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "MachineID:" ascii
        $key_7 = "Path:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Threads:" ascii
        $key_11 = "VideoCard:" ascii
        $key_12 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}