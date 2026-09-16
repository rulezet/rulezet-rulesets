rule Vidar_cystack_cf73c35c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_cf73c35c"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Arena Breakout:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "PUBG:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "Threads:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "VideoCard:" ascii
        $key_19 = "Windows:" ascii
        $key_20 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}