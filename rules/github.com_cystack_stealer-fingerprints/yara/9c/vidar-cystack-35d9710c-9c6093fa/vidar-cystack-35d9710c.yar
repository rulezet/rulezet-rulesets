rule Vidar_cystack_35d9710c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_35d9710c"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "HWID:" ascii
        $key_4 = "Local Time:" ascii
        $key_5 = "Path:" ascii
        $key_6 = "Processor:" ascii
        $key_7 = "RAM:" ascii
        $key_8 = "Threads:" ascii
        $key_9 = "User Name:" ascii
        $key_10 = "VideoCard:" ascii
        $key_11 = "Windows:" ascii
        $key_12 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}