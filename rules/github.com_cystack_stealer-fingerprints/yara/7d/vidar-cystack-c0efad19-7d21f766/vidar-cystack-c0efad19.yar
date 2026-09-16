rule Vidar_cystack_c0efad19
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c0efad19"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "Local Time:" ascii
        $key_7 = "PUBG:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "RISK:" ascii
        $key_11 = "Threads:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "VideoCard:" ascii
        $key_15 = "Windows:" ascii

    condition:
        all of ($key_*)
}