rule Vidar_cystack_03a211e5
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_03a211e5"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Passpartout:" ascii
        $key_11 = "Path:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "SCP:" ascii
        $key_15 = "Supermarket Simulator:" ascii
        $key_16 = "Threads:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "VideoCard:" ascii
        $key_20 = "Wallpaper Engine:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}