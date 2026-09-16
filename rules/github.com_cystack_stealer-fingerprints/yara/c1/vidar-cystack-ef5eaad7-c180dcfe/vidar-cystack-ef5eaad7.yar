rule Vidar_cystack_ef5eaad7
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_ef5eaad7"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "Keyboard Languages:" ascii
        $key_4 = "Local Time:" ascii
        $key_5 = "Processor:" ascii
        $key_6 = "RAM:" ascii
        $key_7 = "Threads:" ascii
        $key_8 = "TimeZone:" ascii
        $key_9 = "User Name:" ascii
        $key_10 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}