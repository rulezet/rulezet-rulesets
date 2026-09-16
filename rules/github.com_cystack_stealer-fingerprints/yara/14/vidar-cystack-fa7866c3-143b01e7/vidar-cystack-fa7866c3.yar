rule Vidar_cystack_fa7866c3
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_fa7866c3"

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
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Kingdom Come:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "METAL GEAR SOLID 3:" ascii
        $key_15 = "METAL GEAR SOLID V:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Mafia II:" ascii
        $key_18 = "PUBG:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "Version:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Wolfenstein II:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}