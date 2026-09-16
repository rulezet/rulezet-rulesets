rule Vidar_cystack_80dd9aab
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_80dd9aab"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "FIND ALL:" ascii
        $key_7 = "FIND ALL 2:" ascii
        $key_8 = "FIND ALL 3:" ascii
        $key_9 = "FIND ALL 4:" ascii
        $key_10 = "FIND ALL 5:" ascii
        $key_11 = "FIND ALL 6:" ascii
        $key_12 = "FIND ALL 8:" ascii
        $key_13 = "FIND ALL 9:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Stronghold Crusader:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}