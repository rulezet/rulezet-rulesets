rule Vidar_cystack_072f79a1
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_072f79a1"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Backrooms:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "GUID:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Ip:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "MachineID:" ascii
        $key_13 = "Mafia:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Sea of Thieves:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}