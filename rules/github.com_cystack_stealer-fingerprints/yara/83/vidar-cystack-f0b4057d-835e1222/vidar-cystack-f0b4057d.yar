rule Vidar_cystack_f0b4057d
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f0b4057d"

    strings:
        $key_0 = "Computer Name:" ascii
        $key_1 = "Cores:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GUID:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "IP:" ascii
        $key_8 = "Local Time:" ascii
        $key_9 = "MachineID:" ascii
        $key_10 = "Path:" ascii
        $key_11 = "Processor:" ascii
        $key_12 = "RAM:" ascii
        $key_13 = "Telegram:" ascii
        $key_14 = "Threads:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "Version:" ascii
        $key_17 = "VideoCard:" ascii
        $key_18 = "Windows:" ascii
        $key_19 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}