rule Vidar_cystack_71b14a47
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_71b14a47"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Black Myth:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "Local Time:" ascii
        $key_7 = "Processor:" ascii
        $key_8 = "RAM:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "TimeZone:" ascii
        $key_11 = "User Name:" ascii
        $key_12 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}