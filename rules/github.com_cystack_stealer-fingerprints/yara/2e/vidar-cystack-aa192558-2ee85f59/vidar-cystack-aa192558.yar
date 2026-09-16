rule Vidar_cystack_aa192558
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_aa192558"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Integrity:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "LocalIPv4:" ascii
        $key_11 = "MachineID:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "SystemTimestamp:" ascii
        $key_16 = "SystemUptime:" ascii
        $key_17 = "TAG:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Wallpaper Hash:" ascii
        $key_23 = "Windows:" ascii

    condition:
        all of ($key_*)
}