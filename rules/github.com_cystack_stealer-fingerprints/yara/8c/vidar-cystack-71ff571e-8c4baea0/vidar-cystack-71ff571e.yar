rule Vidar_cystack_71ff571e
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_71ff571e"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Hotline Miami 2:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Plague Inc:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "RISK:" ascii
        $key_20 = "Stronghold:" ascii
        $key_21 = "The Binding of Isaac:" ascii
        $key_22 = "The Elder Scrolls III:" ascii
        $key_23 = "The Elder Scrolls IV:" ascii
        $key_24 = "The Elder Scrolls V:" ascii
        $key_25 = "The Stanley Parable:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}