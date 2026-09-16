rule Vidar_cystack_81bbc647
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_81bbc647"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "Local Time:" ascii
        $key_7 = "Processor:" ascii
        $key_8 = "RAM:" ascii
        $key_9 = "Threads:" ascii
        $key_10 = "TimeZone:" ascii
        $key_11 = "Umamusume:" ascii
        $key_12 = "User Name:" ascii
        $key_13 = "VideoCard:" ascii
        $key_14 = "Windows:" ascii

    condition:
        all of ($key_*)
}