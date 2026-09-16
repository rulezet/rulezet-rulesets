rule Vidar_cystack_0c072506
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0c072506"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Hollow Knight:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "Path:" ascii
        $key_10 = "Pixel Gun 3D:" ascii
        $key_11 = "Processor:" ascii
        $key_12 = "RAM:" ascii
        $key_13 = "The Seven Deadly Sins:" ascii
        $key_14 = "Threads:" ascii
        $key_15 = "TimeZone:" ascii
        $key_16 = "User Name:" ascii
        $key_17 = "VideoCard:" ascii
        $key_18 = "Windows:" ascii
        $key_19 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}