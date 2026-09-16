rule Vidar_cystack_812b1e80
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_812b1e80"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bad Parenting 1:" ascii
        $key_2 = "Bully:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "DEEEER Simulator:" ascii
        $key_7 = "DORAEMON STORY OF SEASONS:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "Grand Theft Auto:" ascii
        $key_11 = "Granny:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "NARUTO SHIPPUDEN:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Samurai Jack:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}