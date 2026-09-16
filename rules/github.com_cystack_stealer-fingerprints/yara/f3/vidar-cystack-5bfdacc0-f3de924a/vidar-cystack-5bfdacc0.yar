rule Vidar_cystack_5bfdacc0
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5bfdacc0"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires II:" ascii
        $key_2 = "Age of Empires III:" ascii
        $key_3 = "Battlefield:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Grand Theft Auto:" ascii
        $key_9 = "Grand Theft Auto IV:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "Rise of Nations:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Wolfenstein:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}