rule Vidar_cystack_cba41527
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_cba41527"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "HFSQL:" ascii
        $key_4 = "Keyboard Languages:" ascii
        $key_5 = "Local Time:" ascii
        $key_6 = "Processor:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "Threads:" ascii
        $key_9 = "TimeZone:" ascii
        $key_10 = "User Name:" ascii
        $key_11 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}