rule Vidar_cystack_6e6ac3a3
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6e6ac3a3"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "PICO PARK:" ascii
        $key_11 = "Path:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "Rent A Car Simulator 24:" ascii
        $key_15 = "Shadowverse:" ascii
        $key_16 = "Threads:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "Tobacco Shop Simulator:" ascii
        $key_19 = "Together in Forgotten Lands:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "Version:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}