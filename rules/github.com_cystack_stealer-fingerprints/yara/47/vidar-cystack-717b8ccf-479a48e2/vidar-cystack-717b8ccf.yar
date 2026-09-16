rule Vidar_cystack_717b8ccf
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_717b8ccf"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Install Date:" ascii
        $key_5 = "Keyboard Languages:" ascii
        $key_6 = "Local Time:" ascii
        $key_7 = "Mini World:" ascii
        $key_8 = "Processor:" ascii
        $key_9 = "RAM:" ascii
        $key_10 = "Threads:" ascii
        $key_11 = "TimeZone:" ascii
        $key_12 = "User Name:" ascii
        $key_13 = "VideoCard:" ascii
        $key_14 = "Windows:" ascii

    condition:
        all of ($key_*)
}