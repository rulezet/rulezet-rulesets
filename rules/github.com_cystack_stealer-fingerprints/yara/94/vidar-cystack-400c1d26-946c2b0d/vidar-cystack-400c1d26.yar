rule Vidar_cystack_400c1d26
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_400c1d26"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Banker Simulator:" ascii
        $key_2 = "Bum:" ascii
        $key_3 = "Cafe Owner Simulator:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Deconstruction Simulator:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "Factory Outlet Simulator:" ascii
        $key_11 = "Garage Flipper:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "Neighbors:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "Quarantine Zone:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Sunset Motel:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "Tobacco Shop Simulator:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}