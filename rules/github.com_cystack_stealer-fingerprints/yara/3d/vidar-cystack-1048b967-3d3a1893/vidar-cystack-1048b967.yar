rule Vidar_cystack_1048b967
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1048b967"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Counter-Strike:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Keyboard Languages:" ascii
        $key_5 = "Local Time:" ascii
        $key_6 = "Processor:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "The Binding of Isaac:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "TimeZone:" ascii
        $key_11 = "User Name:" ascii
        $key_12 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}