rule Vidar_cystack_158f6ebc
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_158f6ebc"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Display Resolution:" ascii
        $key_3 = "GUID:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Local Time:" ascii
        $key_6 = "Path:" ascii
        $key_7 = "Processor:" ascii
        $key_8 = "RAM:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "User Name:" ascii
        $key_11 = "VideoCard:" ascii
        $key_12 = "Windows:" ascii
        $key_13 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}