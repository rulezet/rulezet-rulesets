rule Vidar_cystack_79fdf130
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_79fdf130"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Armored Core 6:" ascii
        $key_2 = "BLUE REFLECTION:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Dragon Ball Z:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Granblue Fantasy:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Metal Gear Rising:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "Punishing:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "Version:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}