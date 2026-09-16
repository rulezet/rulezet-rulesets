rule Vidar_cystack_bff562ac
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bff562ac"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "GUID:" ascii
        $key_7 = "Grand Theft Auto:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Hitman:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Kingdom Come:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Mafia:" ascii
        $key_17 = "Mafia II:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Wolfenstein:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}