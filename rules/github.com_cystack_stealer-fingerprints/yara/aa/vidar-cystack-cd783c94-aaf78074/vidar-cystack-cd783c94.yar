rule Vidar_cystack_cd783c94
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_cd783c94"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GUID:" ascii
        $key_6 = "Grand Theft Auto:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "Hollow Knight:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MachineID:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "SpongeBob SquarePants:" ascii
        $key_18 = "Teenage Mutant Ninja Turtles Arcade:" ascii
        $key_19 = "Threads:" ascii
        $key_20 = "TimeZone:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}