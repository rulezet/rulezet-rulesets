rule Vidar_cystack_f90a0617
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f90a0617"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Fallout:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Hollow Knight:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Potion Craft:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "The Elder Scrolls V:" ascii
        $key_21 = "The Walking Dead:" ascii
        $key_22 = "The Witcher 2:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "Thronebreaker:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "Version:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}