rule Vidar_cystack_9867e6ae
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_9867e6ae"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Dune:" ascii
        $key_6 = "Fallout:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "Kingdom Come:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "Men of War:" ascii
        $key_13 = "Motor Town:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "SCP:" ascii
        $key_17 = "Species:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "User Name:" ascii
        $key_21 = "VideoCard:" ascii
        $key_22 = "Windows:" ascii
        $key_23 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}