rule Vidar_cystack_d56fd7d6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_d56fd7d6"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Processor:" ascii
        $key_2 = "RAM:" ascii
        $key_3 = "Threads:" ascii
        $key_4 = "TimeZone:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}