rule Vidar_cystack_5405b17a
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5405b17a"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "Local Time:" ascii
        $key_7 = "Motor Town:" ascii
        $key_8 = "Only Up:" ascii
        $key_9 = "Path:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "RAM:" ascii
        $key_12 = "Taxi Life:" ascii
        $key_13 = "Threads:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "VideoCard:" ascii
        $key_17 = "Windows:" ascii
        $key_18 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}