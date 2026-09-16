rule Vidar_cystack_c0038779
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c0038779"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Install Date:" ascii
        $key_6 = "Keyboard Languages:" ascii
        $key_7 = "LEGO Star Wars:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "The Walking Dead:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "User Name:" ascii
        $key_15 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}