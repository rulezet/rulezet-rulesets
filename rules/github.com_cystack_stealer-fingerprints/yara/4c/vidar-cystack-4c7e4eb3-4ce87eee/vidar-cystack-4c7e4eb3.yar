rule Vidar_cystack_4c7e4eb3
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_4c7e4eb3"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Ip:" ascii
        $key_6 = "Keyboard Languages:" ascii
        $key_7 = "Local Time:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Threads:" ascii
        $key_11 = "TimeZone:" ascii
        $key_12 = "User Name:" ascii
        $key_13 = "Version Date:" ascii
        $key_14 = "VideoCard:" ascii
        $key_15 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}