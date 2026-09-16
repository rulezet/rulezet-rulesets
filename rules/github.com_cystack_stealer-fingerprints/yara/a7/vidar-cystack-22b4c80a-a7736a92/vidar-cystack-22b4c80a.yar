rule Vidar_cystack_22b4c80a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_22b4c80a"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Counter-Strike:" ascii
        $key_3 = "Counter-Strike Nexon:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Grand Theft Auto:" ascii
        $key_6 = "Keyboard Languages:" ascii
        $key_7 = "Local Time:" ascii
        $key_8 = "PUBG:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "Threads:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "VideoCard:" ascii
        $key_15 = "Warface:" ascii

    condition:
        all of ($key_*)
}