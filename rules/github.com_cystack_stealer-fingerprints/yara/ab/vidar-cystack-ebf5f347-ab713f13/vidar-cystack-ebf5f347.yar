rule Vidar_cystack_ebf5f347
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_ebf5f347"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Integrity:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "LocalIPv4:" ascii
        $key_9 = "MachineID:" ascii
        $key_10 = "Path:" ascii
        $key_11 = "Processor:" ascii
        $key_12 = "RAM:" ascii
        $key_13 = "SystemTimestamp:" ascii
        $key_14 = "SystemUptime:" ascii
        $key_15 = "TAG:" ascii
        $key_16 = "Threads:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "VideoCard:" ascii
        $key_20 = "Wallpaper Hash:" ascii
        $key_21 = "Windows:" ascii

    condition:
        all of ($key_*)
}