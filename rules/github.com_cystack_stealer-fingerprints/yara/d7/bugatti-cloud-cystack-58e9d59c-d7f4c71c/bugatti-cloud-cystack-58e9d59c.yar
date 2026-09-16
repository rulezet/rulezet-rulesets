rule Bugatti_Cloud_cystack_58e9d59c
{
    meta:
        family = "Bugatti Cloud"
        fingerprint_id = "cystack_58e9d59c"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Evony:" ascii
        $key_2 = "Processor:" ascii
        $key_3 = "RAM:" ascii
        $key_4 = "Threads:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}