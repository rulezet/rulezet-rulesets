rule Vidar_cystack_c51a66f3
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c51a66f3"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Keyboard Languages:" ascii
        $key_5 = "Local Time:" ascii
        $key_6 = "PUBG:" ascii
        $key_7 = "Processor:" ascii
        $key_8 = "RAM:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "TimeZone:" ascii
        $key_11 = "User Name:" ascii
        $key_12 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}