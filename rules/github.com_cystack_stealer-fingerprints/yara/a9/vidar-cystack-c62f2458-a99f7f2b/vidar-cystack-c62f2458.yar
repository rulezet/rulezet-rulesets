rule Vidar_cystack_c62f2458
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c62f2458"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "LEGO STAR WARS:" ascii
        $key_7 = "Local Time:" ascii
        $key_8 = "Pixel Gun 3D:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "Threads:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "VideoCard:" ascii
        $key_15 = "Windows:" ascii

    condition:
        all of ($key_*)
}