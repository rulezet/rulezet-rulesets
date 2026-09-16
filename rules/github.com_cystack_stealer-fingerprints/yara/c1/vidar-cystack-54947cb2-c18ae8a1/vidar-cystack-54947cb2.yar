rule Vidar_cystack_54947cb2
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_54947cb2"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires IV:" ascii
        $key_2 = "Company of Heroes:" ascii
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
        $key_15 = "Threads:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "VideoCard:" ascii
        $key_19 = "Windows:" ascii
        $key_20 = "Work Dir:" ascii
        $key_21 = "Zen Chess:" ascii

    condition:
        all of ($key_*)
}