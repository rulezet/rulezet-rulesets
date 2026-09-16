rule RedlineLike_Stealer_cystack_ee3d861c
{
    meta:
        family = "RedlineLike Stealer"
        fingerprint_id = "cystack_ee3d861c"

    strings:
        $key_0 = "Admin Group:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Display Resolution:" ascii
        $key_4 = "Domain Name:" ascii
        $key_5 = "Graphics card:" ascii
        $key_6 = "IP:" ascii
        $key_7 = "Installed RAM:" ascii
        $key_8 = "Integrity:" ascii
        $key_9 = "Keyboard Language:" ascii
        $key_10 = "MachineID:" ascii
        $key_11 = "Operation System:" ascii
        $key_12 = "Processor:" ascii
        $key_13 = "System Language:" ascii
        $key_14 = "TimeZone:" ascii
        $key_15 = "User Name:" ascii
        $key_16 = "UserLanguage:" ascii
        $key_17 = "Wallpaper Hash:" ascii

    condition:
        all of ($key_*)
}