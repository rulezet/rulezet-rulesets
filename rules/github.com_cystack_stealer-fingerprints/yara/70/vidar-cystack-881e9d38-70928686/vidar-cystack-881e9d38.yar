rule Vidar_cystack_881e9d38
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_881e9d38"

    strings:
        $key_0 = "ACD/Labs 2024 Freeware in C:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Backrooms:" ascii
        $key_3 = "Blood:" ascii
        $key_4 = "Blood II:" ascii
        $key_5 = "CATACOMBS:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Counter-Strike:" ascii
        $key_9 = "Country:" ascii
        $key_10 = "Date:" ascii
        $key_11 = "Display Resolution:" ascii
        $key_12 = "GUID:" ascii
        $key_13 = "Grand Theft Auto:" ascii
        $key_14 = "HWID:" ascii
        $key_15 = "Half-Life:" ascii
        $key_16 = "Half-Life Deathmatch:" ascii
        $key_17 = "Hollow Knight:" ascii
        $key_18 = "Hotline Miami 2:" ascii
        $key_19 = "Install Date:" ascii
        $key_20 = "Ip:" ascii
        $key_21 = "Keyboard Languages:" ascii
        $key_22 = "Local Time:" ascii
        $key_23 = "MachineID:" ascii
        $key_24 = "POSTAL 4:" ascii
        $key_25 = "Path:" ascii
        $key_26 = "Processor:" ascii
        $key_27 = "Quake III:" ascii
        $key_28 = "RAM:" ascii
        $key_29 = "Sand:" ascii
        $key_30 = "Scorn:" ascii
        $key_31 = "The Binding of Isaac:" ascii
        $key_32 = "Threads:" ascii
        $key_33 = "TimeZone:" ascii
        $key_34 = "User Name:" ascii
        $key_35 = "Version:" ascii
        $key_36 = "VideoCard:" ascii
        $key_37 = "Windows:" ascii
        $key_38 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}