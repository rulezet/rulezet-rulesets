rule Vidar_cystack_075184eb
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_075184eb"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Blackjack 21:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Counter-Strike:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Grand Theft Auto:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Pixel Gun 3D:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}