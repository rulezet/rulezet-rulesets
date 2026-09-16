rule Vidar_cystack_dbd3f3d6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_dbd3f3d6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Alice:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Fallout:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "GameMaker:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Hitman:" ascii
        $key_13 = "IP:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Telegram:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "Version:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Wolfenstein:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}