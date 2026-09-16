rule Vidar_cystack_63443b5d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_63443b5d"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Kebab Simulator:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Ocean World:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Pixel Gun 3D:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Schedule I:" ascii
        $key_21 = "Telegram:" ascii
        $key_22 = "Thief Simulator 2:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "Version:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}