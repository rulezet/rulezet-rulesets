rule Vidar_cystack_c50f6df9
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c50f6df9"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "The Escapists:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "User Name:" ascii
        $key_15 = "VideoCard:" ascii
        $key_16 = "Windows:" ascii
        $key_17 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}