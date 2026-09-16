rule Vidar_cystack_c19c035d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c19c035d"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Factory Outlet Simulator:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MachineID:" ascii
        $key_14 = "Path:" ascii
        $key_15 = "Plague Inc:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RACCOIN:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Telegram:" ascii
        $key_20 = "The Witcher 3:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "Version:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii
        $key_28 = "Zero Stress King:" ascii

    condition:
        all of ($key_*)
}