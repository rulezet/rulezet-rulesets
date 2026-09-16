rule Vidar_cystack_07bae8ca
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_07bae8ca"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "FTL:" ascii
        $key_7 = "Fallout:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "NieR:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "Threads:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "Version:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}