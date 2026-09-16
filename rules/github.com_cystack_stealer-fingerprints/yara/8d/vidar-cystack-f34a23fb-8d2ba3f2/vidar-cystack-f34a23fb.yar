rule Vidar_cystack_f34a23fb
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f34a23fb"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Alice:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "RAM:" ascii
        $key_12 = "Ruindog:" ascii
        $key_13 = "Stick Fight:" ascii
        $key_14 = "The Witcher:" ascii
        $key_15 = "The Witcher 2:" ascii
        $key_16 = "The Witcher 3:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}