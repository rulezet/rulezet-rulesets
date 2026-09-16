rule Vidar_cystack_55b0f121
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_55b0f121"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires III:" ascii
        $key_2 = "Age of Mythology:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Detroit:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "The Walking Dead:" ascii
        $key_17 = "The Witcher 3:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}