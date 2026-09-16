rule Bugatti_Cloud_cystack_1aa0f2d0
{
    meta:
        family = "Bugatti Cloud"
        fingerprint_id = "cystack_1aa0f2d0"

    strings:
        $key_0 = "Age of Empires III:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Processor:" ascii
        $key_3 = "RAM:" ascii
        $key_4 = "Threads:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}