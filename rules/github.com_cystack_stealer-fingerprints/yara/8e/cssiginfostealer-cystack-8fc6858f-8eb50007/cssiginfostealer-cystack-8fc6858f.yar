rule CSSigInfoStealer_cystack_8fc6858f
{
    meta:
        family = "CSSigInfoStealer"
        fingerprint_id = "cystack_8fc6858f"

    strings:
        $key_0 = "Antivirus:" ascii
        $key_1 = "Build Date:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Configuration:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Elevated:" ascii
        $key_7 = "Execution Path:" ascii
        $key_8 = "Graphics Card:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "IP Address:" ascii
        $key_11 = "Installed RAM:" ascii
        $key_12 = "Netbios:" ascii
        $key_13 = "Processor:" ascii
        $key_14 = "Processor Cores:" ascii
        $key_15 = "Processor Threads:" ascii
        $key_16 = "Time:" ascii
        $key_17 = "User:" ascii
        $key_18 = "User Language:" ascii
        $key_19 = "User Name:" ascii

    condition:
        all of ($key_*)
}