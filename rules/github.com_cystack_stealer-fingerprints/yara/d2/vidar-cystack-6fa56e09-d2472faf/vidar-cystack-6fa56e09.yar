rule Vidar_cystack_6fa56e09
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6fa56e09"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Beyond:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Detroit:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Hitman:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Sleeping Dogs:" ascii
        $key_21 = "The Walking Dead:" ascii
        $key_22 = "The Witcher:" ascii
        $key_23 = "The Witcher 2:" ascii
        $key_24 = "The Witcher 3:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Watchmen:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}