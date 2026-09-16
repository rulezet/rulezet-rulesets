rule Vidar_cystack_2955c267
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_2955c267"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Arma 2:" ascii
        $key_2 = "Batman:" ascii
        $key_3 = "Call of Duty:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Hitman:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "NARUTO SHIPPUDEN:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Plague Inc:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii
        $key_28 = "XCOM:" ascii

    condition:
        all of ($key_*)
}