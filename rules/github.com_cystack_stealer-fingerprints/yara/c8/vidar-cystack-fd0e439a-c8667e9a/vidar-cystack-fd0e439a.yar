rule Vidar_cystack_fd0e439a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_fd0e439a"

    strings:
        $key_0 = "Adventure Time:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Processor:" ascii
        $key_3 = "RAM:" ascii
        $key_4 = "Threads:" ascii
        $key_5 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}