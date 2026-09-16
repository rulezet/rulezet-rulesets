rule Vidar_cystack_70308063
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_70308063"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Deus Ex:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Elven Legacy:" ascii
        $key_8 = "Heroes of Might and Magic:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "Nexus:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "Sphere:" ascii
        $key_17 = "The Bureau:" ascii
        $key_18 = "Threads:" ascii
        $key_19 = "TimeZone:" ascii
        $key_20 = "Total War:" ascii
        $key_21 = "UFO:" ascii
        $key_22 = "User Name:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Windows:" ascii
        $key_25 = "Work Dir:" ascii
        $key_26 = "X-COM:" ascii
        $key_27 = "XCOM:" ascii

    condition:
        all of ($key_*)
}