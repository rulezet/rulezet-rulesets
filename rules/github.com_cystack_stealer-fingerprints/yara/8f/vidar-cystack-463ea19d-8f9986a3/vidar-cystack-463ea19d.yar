rule Vidar_cystack_463ea19d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_463ea19d"

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
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Kingdom Come:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "METAL GEAR SOLID 3:" ascii
        $key_14 = "METAL GEAR SOLID V:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Mafia II:" ascii
        $key_17 = "PUBG:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Wolfenstein II:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}