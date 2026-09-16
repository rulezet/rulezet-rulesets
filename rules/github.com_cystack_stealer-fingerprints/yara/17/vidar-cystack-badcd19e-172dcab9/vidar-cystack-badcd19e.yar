rule Vidar_cystack_badcd19e
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_badcd19e"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Dying Light:" ascii
        $key_7 = "Hunt:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Metaphor:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "The Binding of Isaac:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "Version:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}