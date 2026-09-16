rule Vidar_cystack_f79fdc92
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f79fdc92"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Install Date:" ascii
        $key_6 = "Ip:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "Threads:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "VideoCard:" ascii
        $key_15 = "Warplanes:" ascii
        $key_16 = "Windows:" ascii
        $key_17 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}