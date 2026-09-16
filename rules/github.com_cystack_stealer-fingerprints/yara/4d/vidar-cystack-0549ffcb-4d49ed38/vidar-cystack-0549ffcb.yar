rule Vidar_cystack_0549ffcb
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0549ffcb"

    strings:
        $key_0 = "ANNO:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Academy Love Saga:" ascii
        $key_3 = "Batman:" ascii
        $key_4 = "Bloodstained:" ascii
        $key_5 = "Cinderella Phenomenon:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "HWID:" ascii
        $key_13 = "Hollow Knight:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Kingdom Come:" ascii
        $key_18 = "Local Time:" ascii
        $key_19 = "MachineID:" ascii
        $key_20 = "NieR:" ascii
        $key_21 = "Path:" ascii
        $key_22 = "Pathfinder:" ascii
        $key_23 = "Processor:" ascii
        $key_24 = "RAM:" ascii
        $key_25 = "RoboCop:" ascii
        $key_26 = "Ryse:" ascii
        $key_27 = "Skul:" ascii
        $key_28 = "The Great Villainess:" ascii
        $key_29 = "The Hungry Lamb:" ascii
        $key_30 = "The Witcher:" ascii
        $key_31 = "The Witcher 3:" ascii
        $key_32 = "Threads:" ascii
        $key_33 = "TimeZone:" ascii
        $key_34 = "User Name:" ascii
        $key_35 = "VideoCard:" ascii
        $key_36 = "Windows:" ascii
        $key_37 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}