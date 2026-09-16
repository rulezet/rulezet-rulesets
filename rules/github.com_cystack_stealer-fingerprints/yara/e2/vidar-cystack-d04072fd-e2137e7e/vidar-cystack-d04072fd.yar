rule Vidar_cystack_d04072fd
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_d04072fd"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Counter-Strike:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Day of Defeat:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Grand Theft Auto IV:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Half-Life 2:" ascii
        $key_12 = "Half-Life Deathmatch:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Kill It With Fire:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Mafia:" ascii
        $key_20 = "PICO PARK:" ascii
        $key_21 = "Path:" ascii
        $key_22 = "Processor:" ascii
        $key_23 = "RAM:" ascii
        $key_24 = "Schedule I:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "Version:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}