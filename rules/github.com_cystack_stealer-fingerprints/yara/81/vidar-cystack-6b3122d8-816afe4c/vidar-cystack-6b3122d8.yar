rule Vidar_cystack_6b3122d8
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6b3122d8"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "Magic Pussy:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "Projekt:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "Rise of Nations:" ascii
        $key_17 = "Sex Coach:" ascii
        $key_18 = "The Seven Realms - Realm 3:" ascii
        $key_19 = "Threads:" ascii
        $key_20 = "TimeZone:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}