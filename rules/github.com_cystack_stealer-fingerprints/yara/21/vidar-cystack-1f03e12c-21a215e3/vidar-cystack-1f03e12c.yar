rule Vidar_cystack_1f03e12c
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1f03e12c"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Counter-Strike:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Fallout:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "Grand Theft Auto:" ascii
        $key_12 = "Grand Theft Auto IV:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Halo:" ascii
        $key_15 = "Install Date:" ascii
        $key_16 = "Ip:" ascii
        $key_17 = "Keyboard Languages:" ascii
        $key_18 = "Local Time:" ascii
        $key_19 = "MachineID:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "SpongeBob SquarePants:" ascii
        $key_24 = "The Elder Scrolls IV:" ascii
        $key_25 = "The Elder Scrolls V:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "Version:" ascii
        $key_30 = "VideoCard:" ascii
        $key_31 = "Windows:" ascii
        $key_32 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}