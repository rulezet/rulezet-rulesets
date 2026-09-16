rule Vidar_cystack_96c6d1f2
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_96c6d1f2"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Arena Breakout:" ascii
        $key_2 = "Backrooms:" ascii
        $key_3 = "Black Pine:" ascii
        $key_4 = "Blackjack 21:" ascii
        $key_5 = "Call of Duty:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Disney Epic Mickey:" ascii
        $key_11 = "Display Resolution:" ascii
        $key_12 = "Dying Light:" ascii
        $key_13 = "GUID:" ascii
        $key_14 = "HWID:" ascii
        $key_15 = "Half-Life:" ascii
        $key_16 = "Install Date:" ascii
        $key_17 = "Ip:" ascii
        $key_18 = "Keyboard Languages:" ascii
        $key_19 = "Local Time:" ascii
        $key_20 = "MachineID:" ascii
        $key_21 = "Path:" ascii
        $key_22 = "Processor:" ascii
        $key_23 = "RAM:" ascii
        $key_24 = "The Backrooms:" ascii
        $key_25 = "The Elder Scrolls V:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}