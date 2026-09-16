rule Vidar_cystack_1e8a32e1
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1e8a32e1"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Batman:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MachineID:" ascii
        $key_14 = "Metro Conflict:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "Telegram:" ascii
        $key_19 = "The Witcher 3:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "Tobacco Shop Simulator:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "Version:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}