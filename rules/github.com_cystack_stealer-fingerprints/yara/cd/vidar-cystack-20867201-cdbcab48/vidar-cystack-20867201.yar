rule Vidar_cystack_20867201
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_20867201"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Asphalt 9:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "Processor:" ascii
        $key_12 = "RAM:" ascii
        $key_13 = "Threads:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "VideoCard:" ascii
        $key_17 = "Windows:" ascii
        $key_18 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}