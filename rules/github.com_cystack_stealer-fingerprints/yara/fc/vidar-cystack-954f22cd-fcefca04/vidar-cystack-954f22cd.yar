rule Vidar_cystack_954f22cd
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_954f22cd"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "Local Time:" ascii
        $key_7 = "Operation:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "Project Reality:" ascii
        $key_10 = "RAM:" ascii
        $key_11 = "SCP:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "TimeZone:" ascii
        $key_14 = "User Name:" ascii
        $key_15 = "VideoCard:" ascii
        $key_16 = "Windows:" ascii

    condition:
        all of ($key_*)
}