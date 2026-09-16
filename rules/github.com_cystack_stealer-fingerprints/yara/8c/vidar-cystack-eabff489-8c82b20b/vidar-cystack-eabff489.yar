rule Vidar_cystack_eabff489
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_eabff489"

    strings:
        $key_0 = "A3:" ascii
        $key_1 = "ARK:" ascii
        $key_2 = "AV:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "DRAGON BALL:" ascii
        $key_7 = "DRAGON BALL Z:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "STAR WARS Jedi:" ascii
        $key_18 = "Seven Knights Re:" ascii
        $key_19 = "Solo Leveling:" ascii
        $key_20 = "The Seven Deadly Sins:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}