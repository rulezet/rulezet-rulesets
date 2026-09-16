rule Vidar_cystack_8b4a2b6f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_8b4a2b6f"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Depths Of Horror:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Local Time:" ascii
        $key_11 = "Path:" ascii
        $key_12 = "Pixel Gun 3D:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "Schedule I:" ascii
        $key_16 = "Subnautica:" ascii
        $key_17 = "Threads:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "Version:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}