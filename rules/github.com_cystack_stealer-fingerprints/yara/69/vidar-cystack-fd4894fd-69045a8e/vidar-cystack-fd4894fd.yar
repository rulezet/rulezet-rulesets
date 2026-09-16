rule Vidar_cystack_fd4894fd
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_fd4894fd"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Processor:" ascii
        $key_2 = "RAM:" ascii
        $key_3 = "SAS:" ascii
        $key_4 = "Threads:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}