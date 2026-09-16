rule Vidar_cystack_0532f678
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0532f678"

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
        $key_14 = "Jacksmith:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "PUBG:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "The Elder Scrolls II:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "Version:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Warhammer:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}