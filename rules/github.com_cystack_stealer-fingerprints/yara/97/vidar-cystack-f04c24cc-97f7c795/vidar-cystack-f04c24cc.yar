rule Vidar_cystack_f04c24cc
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f04c24cc"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "IP:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Threads:" ascii
        $key_11 = "TimeZone:" ascii
        $key_12 = "User Name:" ascii
        $key_13 = "VideoCard:" ascii
        $key_14 = "Windows:" ascii
        $key_15 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}