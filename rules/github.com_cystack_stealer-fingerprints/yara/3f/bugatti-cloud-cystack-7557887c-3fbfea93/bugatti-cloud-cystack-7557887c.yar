rule Bugatti_Cloud_cystack_7557887c
{
    meta:
        family = "Bugatti Cloud"
        fingerprint_id = "cystack_7557887c"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "PUBG:" ascii
        $key_2 = "Processor:" ascii
        $key_3 = "RAM:" ascii
        $key_4 = "Threads:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}