rule Vidar_cystack_c87865b1
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c87865b1"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Arena Breakout:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "Sunset Motel:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "User Name:" ascii
        $key_15 = "VideoCard:" ascii
        $key_16 = "Windows:" ascii
        $key_17 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}