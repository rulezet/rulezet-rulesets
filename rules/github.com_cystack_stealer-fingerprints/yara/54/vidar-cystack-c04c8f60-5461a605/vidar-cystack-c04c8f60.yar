rule Vidar_cystack_c04c8f60
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c04c8f60"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Backrooms:" ascii
        $key_2 = "Borderlands:" ascii
        $key_3 = "Call of Duty:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Counter-Strike:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Insurgency:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "Schedule I:" ascii
        $key_19 = "Talisman:" ascii
        $key_20 = "The Binding of Isaac:" ascii
        $key_21 = "The Stanley Parable:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}