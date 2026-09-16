rule Vidar_cystack_1e1c7fec
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1e1c7fec"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Fallout:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Half-Life 2:" ascii
        $key_11 = "Hotline Miami 2:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Max Payne 2:" ascii
        $key_18 = "Oddworld:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "The Witcher:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Wolfenstein:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}