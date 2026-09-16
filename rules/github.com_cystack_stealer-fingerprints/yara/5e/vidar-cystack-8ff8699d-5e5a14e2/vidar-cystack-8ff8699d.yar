rule Vidar_cystack_8ff8699d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_8ff8699d"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Airship:" ascii
        $key_3 = "Bang-On Balls:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Half-Life 2:" ascii
        $key_12 = "Half-Life Deathmatch:" ascii
        $key_13 = "Hunt:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Insurgency:" ascii
        $key_16 = "Ip:" ascii
        $key_17 = "Keyboard Languages:" ascii
        $key_18 = "Local Time:" ascii
        $key_19 = "MachineID:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Pathfinder:" ascii
        $key_22 = "Processor:" ascii
        $key_23 = "RAM:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "Trine 4:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Warhammer:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}