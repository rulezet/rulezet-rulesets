rule Vidar_cystack_14e7b07f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_14e7b07f"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Cronos:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Halo:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Ip:" ascii
        $key_12 = "Kena:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "The Walking Dead:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "Unknown 9:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "Version:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}