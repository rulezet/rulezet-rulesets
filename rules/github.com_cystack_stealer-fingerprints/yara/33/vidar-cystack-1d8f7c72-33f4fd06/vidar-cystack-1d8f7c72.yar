rule Vidar_cystack_1d8f7c72
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1d8f7c72"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Asphalt 9:" ascii
        $key_2 = "Cafe Owner Simulator:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Ip:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Path:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "RISK:" ascii
        $key_16 = "Stormworks:" ascii
        $key_17 = "Thief Simulator 2:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}