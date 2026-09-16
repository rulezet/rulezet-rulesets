rule Vidar_cystack_67f88774
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_67f88774"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Call of Duty 4:" ascii
        $key_3 = "Call to Arms - Gates of Hell:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Grand Theft Auto IV:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}