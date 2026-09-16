rule Vidar_cystack_03b7ea97
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_03b7ea97"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "Threads:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}