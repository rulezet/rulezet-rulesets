rule Vidar_cystack_dc209d9c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_dc209d9c"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Chef Life:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cooking Simulator 2:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Keyboard Languages:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "Microsoft Flight Simulator X:" ascii
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