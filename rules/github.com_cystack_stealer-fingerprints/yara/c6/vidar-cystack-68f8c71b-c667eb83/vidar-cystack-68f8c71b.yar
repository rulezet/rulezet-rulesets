rule Vidar_cystack_68f8c71b
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_68f8c71b"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Aurora Hills:" ascii
        $key_2 = "Car Dealer Simulator:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Crime Simulator:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "JDM:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "PUBG:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Supermarket Simulator:" ascii
        $key_18 = "TCG Card Shop Simulator:" ascii
        $key_19 = "Threads:" ascii
        $key_20 = "TimeZone:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}