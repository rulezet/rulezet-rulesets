rule Vidar_cystack_bdabb5cf
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bdabb5cf"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Keyboard Languages:" ascii
        $key_2 = "Local Time:" ascii
        $key_3 = "Processor:" ascii
        $key_4 = "RAM:" ascii
        $key_5 = "Threads:" ascii
        $key_6 = "TimeZone:" ascii
        $key_7 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}