rule Vidar_cystack_20cc2bf3
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_20cc2bf3"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Aliens:" ascii
        $key_2 = "Among Us 3D:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Divinity:" ascii
        $key_9 = "Grand Theft Auto IV:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "Mafia:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "RoboCop:" ascii
        $key_19 = "SCP:" ascii
        $key_20 = "Species:" ascii
        $key_21 = "Surgeon Simulator:" ascii
        $key_22 = "The Expanse:" ascii
        $key_23 = "The Witcher 3:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "Total War:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}