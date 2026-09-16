rule Vidar_cystack_f5aa6ad6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f5aa6ad6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Digimon World:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MY HERO ACADEMIA:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Mi pobre pajerito:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Rune Factory:" ascii
        $key_20 = "Sex and the Furry Titty 3:" ascii
        $key_21 = "Telegram:" ascii
        $key_22 = "The Witcher:" ascii
        $key_23 = "The Witcher 2:" ascii
        $key_24 = "The Witcher 3:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "UNDER NIGHT IN-BIRTH II Sys:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "Version:" ascii
        $key_30 = "VideoCard:" ascii
        $key_31 = "Windows:" ascii
        $key_32 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}