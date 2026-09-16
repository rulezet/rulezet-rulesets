rule Vidar_cystack_78b5d9b7
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_78b5d9b7"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Cafe Owner Simulator:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "Gas Station Simulator:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "IP:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "PUBG:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Saloon Simulator:" ascii
        $key_20 = "Telegram:" ascii
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