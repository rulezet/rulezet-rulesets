rule Vidar_cystack_5b928f4d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5b928f4d"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bakery Cafe Simulator:" ascii
        $key_2 = "Bum:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Crime Simulator:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "Threads:" ascii
        $key_15 = "TimeZone:" ascii
        $key_16 = "User Name:" ascii
        $key_17 = "VideoCard:" ascii
        $key_18 = "Windows:" ascii
        $key_19 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}