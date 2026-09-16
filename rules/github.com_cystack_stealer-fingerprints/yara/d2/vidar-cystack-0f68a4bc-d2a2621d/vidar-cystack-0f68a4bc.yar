rule Vidar_cystack_0f68a4bc
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0f68a4bc"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Arena Breakout:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MachineID:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Telegram:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "Umamusume:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "Version:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Windows:" ascii
        $key_25 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}