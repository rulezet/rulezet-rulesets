rule Vidar_cystack_6a074eb6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6a074eb6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "Install Date:" ascii
        $key_6 = "Keyboard Languages:" ascii
        $key_7 = "Local Time:" ascii
        $key_8 = "Path:" ascii
        $key_9 = "Processor:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "Threads:" ascii
        $key_12 = "TimeZone:" ascii
        $key_13 = "User Name:" ascii
        $key_14 = "VideoCard:" ascii
        $key_15 = "Windows:" ascii
        $key_16 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}