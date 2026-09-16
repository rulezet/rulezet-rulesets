rule Vidar_cystack_25f4cc35
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_25f4cc35"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Counter-Strike:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "First Cut:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Mafia II:" ascii
        $key_16 = "Mafia III:" ascii
        $key_17 = "PUBG:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "Version:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}