rule Vidar_cystack_8d8f05c4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_8d8f05c4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bombergrounds:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Detroit:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Hollow Knight:" ascii
        $key_8 = "Install Date:" ascii
        $key_9 = "Ip:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "METAL GEAR RISING:" ascii
        $key_13 = "Miniland Adventure:" ascii
        $key_14 = "NARUTO TO BORUTO:" ascii
        $key_15 = "Processor:" ascii
        $key_16 = "RAM:" ascii
        $key_17 = "The Binding of Isaac:" ascii
        $key_18 = "The Elder Scrolls V:" ascii
        $key_19 = "Threads:" ascii
        $key_20 = "TimeZone:" ascii
        $key_21 = "User Name:" ascii
        $key_22 = "VideoCard:" ascii
        $key_23 = "Windows:" ascii
        $key_24 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}