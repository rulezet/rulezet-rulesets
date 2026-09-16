rule Vidar_cystack_72b911cf
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_72b911cf"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "GunZ 2:" ascii
        $key_5 = "Install Date:" ascii
        $key_6 = "Keyboard Languages:" ascii
        $key_7 = "Local Time:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Threads:" ascii
        $key_11 = "TimeZone:" ascii
        $key_12 = "User Name:" ascii
        $key_13 = "VideoCard:" ascii
        $key_14 = "Windows:" ascii

    condition:
        all of ($key_*)
}