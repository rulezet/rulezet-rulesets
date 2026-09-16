rule Vidar_cystack_3ae6d4c5
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_3ae6d4c5"

    strings:
        $key_0 = "Blackjack 21:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Keyboard Languages:" ascii
        $key_5 = "Local Time:" ascii
        $key_6 = "Processor:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "Threads:" ascii
        $key_9 = "TimeZone:" ascii
        $key_10 = "User Name:" ascii
        $key_11 = "VideoCard:" ascii
        $key_12 = "Warplanes:" ascii

    condition:
        all of ($key_*)
}