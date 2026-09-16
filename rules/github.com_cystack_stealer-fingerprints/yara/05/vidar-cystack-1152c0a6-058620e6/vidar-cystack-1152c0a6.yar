rule Vidar_cystack_1152c0a6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1152c0a6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Commandos:" ascii
        $key_2 = "Commandos 2:" ascii
        $key_3 = "Commandos 3:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Counter-Strike:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "PUBG:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}