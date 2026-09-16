rule Vidar_cystack_c431f76b
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c431f76b"

    strings:
        $key_0 = "A Plague Tale:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Batman:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Ghost of Tsushima:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "Threads:" ascii
        $key_15 = "TimeZone:" ascii
        $key_16 = "User Name:" ascii
        $key_17 = "VideoCard:" ascii
        $key_18 = "Windows:" ascii
        $key_19 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}