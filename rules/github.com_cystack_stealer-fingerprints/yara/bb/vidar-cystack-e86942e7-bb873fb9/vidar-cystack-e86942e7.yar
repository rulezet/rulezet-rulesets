rule Vidar_cystack_e86942e7
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_e86942e7"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Asphalt 9:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Dragonheir:" ascii
        $key_9 = "FATAL FURY:" ascii
        $key_10 = "FreeStyle 2:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "GWENT:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "NARAKA:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "STALCRAFT:" ascii
        $key_24 = "Shadowverse:" ascii
        $key_25 = "The Witcher 3:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "Torchlight:" ascii
        $key_29 = "User Name:" ascii
        $key_30 = "Version:" ascii
        $key_31 = "VideoCard:" ascii
        $key_32 = "Windows:" ascii
        $key_33 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}