rule Vidar_cystack_34d6cbf6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_34d6cbf6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Alice:" ascii
        $key_2 = "Avatar:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Danganronpa V3:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Dying Light 2:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "Processor:" ascii
        $key_12 = "RAM:" ascii
        $key_13 = "Threads:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}