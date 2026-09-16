rule Vidar_cystack_6a0cf5c4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6a0cf5c4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "RAM:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "Uncrashed:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "VideoCard:" ascii
        $key_17 = "Windows:" ascii
        $key_18 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}