rule Vidar_cystack_46405184
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_46405184"

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
        $key_10 = "Telegram:" ascii
        $key_11 = "Threads:" ascii
        $key_12 = "Version:" ascii
        $key_13 = "VideoCard:" ascii
        $key_14 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}