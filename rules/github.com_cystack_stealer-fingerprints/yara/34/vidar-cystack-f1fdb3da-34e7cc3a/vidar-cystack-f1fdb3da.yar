rule Vidar_cystack_f1fdb3da
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f1fdb3da"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Age of Empires III:" ascii
        $key_3 = "Batman:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Grand Theft Auto:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Half-Life:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Magic:" ascii
        $key_19 = "Passpartout:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "The Binding of Isaac:" ascii
        $key_24 = "The Elder Scrolls V:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "Version:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}