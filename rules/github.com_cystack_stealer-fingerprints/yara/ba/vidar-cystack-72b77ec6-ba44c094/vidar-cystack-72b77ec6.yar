rule Vidar_cystack_72b77ec6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_72b77ec6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "FreeStyle 2:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "PUBG:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "RAM:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "User Name:" ascii
        $key_15 = "VideoCard:" ascii
        $key_16 = "Windows:" ascii

    condition:
        all of ($key_*)
}