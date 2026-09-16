rule Vidar_cystack_43a50c2d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_43a50c2d"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Denos City:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Glowing Stones:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "LustyVerse:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Mafia:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Pledge:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "Projekt:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "Serena:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "Version:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}