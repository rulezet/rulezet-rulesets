rule Bugatti_Cloud_cystack_7d394cf9
{
    meta:
        family = "Bugatti Cloud"
        fingerprint_id = "cystack_7d394cf9"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Processor:" ascii
        $key_2 = "RAM:" ascii
        $key_3 = "Threads:" ascii
        $key_4 = "Umamusume:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}