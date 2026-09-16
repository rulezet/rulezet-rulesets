rule Vidar_cystack_bb9a254d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bb9a254d"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Mesh Agent - 2025-03-06 14:" ascii
        $key_2 = "Processor:" ascii
        $key_3 = "RAM:" ascii
        $key_4 = "Threads:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}