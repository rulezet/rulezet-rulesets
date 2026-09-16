rule Vidar_cystack_6daf9532
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6daf9532"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Date:" ascii
        $key_2 = "GUID:" ascii
        $key_3 = "HWID:" ascii
        $key_4 = "MachineID:" ascii
        $key_5 = "Path:" ascii
        $key_6 = "Processor:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "Sekiro:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}