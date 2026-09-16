rule Vidar_cystack_16d2ee2c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_16d2ee2c"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Arena Breakout:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Darkest Hour:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Ip:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Men of War:" ascii
        $key_13 = "Motor Town:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Rising Storm 2:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}