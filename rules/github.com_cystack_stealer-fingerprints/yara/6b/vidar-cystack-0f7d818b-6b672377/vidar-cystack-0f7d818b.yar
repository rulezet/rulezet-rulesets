rule Vidar_cystack_0f7d818b
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0f7d818b"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "CashKaro:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Image to Video AI:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Ip:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "Text to Sound Effects:" ascii
        $key_15 = "Threads:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "VideoCard:" ascii
        $key_19 = "Windows:" ascii
        $key_20 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}