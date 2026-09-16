rule Vidar_cystack_7ea59dcb
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_7ea59dcb"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "Keyboard Languages:" ascii
        $key_9 = "Local Time:" ascii
        $key_10 = "Monster Hunter:" ascii
        $key_11 = "Path:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "RAM:" ascii
        $key_14 = "RISK:" ascii
        $key_15 = "Threads:" ascii
        $key_16 = "TimeZone:" ascii
        $key_17 = "User Name:" ascii
        $key_18 = "VideoCard:" ascii
        $key_19 = "Warhammer:" ascii
        $key_20 = "Windows:" ascii
        $key_21 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}