rule Vidar_cystack_8cee077d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_8cee077d"

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
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "LustyVerse:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Mafia:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Pledge:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "Projekt:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Serena:" ascii
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