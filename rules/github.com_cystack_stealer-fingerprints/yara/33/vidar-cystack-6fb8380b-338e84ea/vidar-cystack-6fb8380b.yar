rule Vidar_cystack_6fb8380b
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6fb8380b"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Age of Empires IV:" ascii
        $key_3 = "Arena Breakout:" ascii
        $key_4 = "Battlefield:" ascii
        $key_5 = "Cities:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "Grand Theft Auto:" ascii
        $key_12 = "HWID:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "The Elder Scrolls II:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "Version:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Warhammer:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}