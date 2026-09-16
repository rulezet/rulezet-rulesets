rule Vidar_cystack_dd86b4a4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_dd86b4a4"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Display Resolution:" ascii
        $key_2 = "Keyboard Languages:" ascii
        $key_3 = "Local Time:" ascii
        $key_4 = "Processor:" ascii
        $key_5 = "RAM:" ascii
        $key_6 = "Threads:" ascii
        $key_7 = "TimeZone:" ascii
        $key_8 = "User Name:" ascii
        $key_9 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}