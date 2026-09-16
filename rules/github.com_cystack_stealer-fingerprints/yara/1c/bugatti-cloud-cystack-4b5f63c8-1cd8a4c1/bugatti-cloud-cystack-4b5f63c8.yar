rule Bugatti_Cloud_cystack_4b5f63c8
{
    meta:
        family = "Bugatti Cloud"
        fingerprint_id = "cystack_4b5f63c8"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Processor:" ascii
        $key_2 = "RAM:" ascii
        $key_3 = "Threads:" ascii
        $key_4 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}