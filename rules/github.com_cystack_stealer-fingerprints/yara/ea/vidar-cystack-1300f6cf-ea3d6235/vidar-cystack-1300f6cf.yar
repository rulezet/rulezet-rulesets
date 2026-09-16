rule Vidar_cystack_1300f6cf
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1300f6cf"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Blackjack 21:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Dark Hours:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Keyboard Languages:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "MachineID:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "Processor:" ascii
        $key_15 = "RAM:" ascii
        $key_16 = "Threads:" ascii
        $key_17 = "TimeZone:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "Version:" ascii
        $key_20 = "VideoCard:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}