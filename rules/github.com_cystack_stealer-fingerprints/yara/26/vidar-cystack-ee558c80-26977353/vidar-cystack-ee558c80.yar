rule Vidar_cystack_ee558c80
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_ee558c80"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Backrooms:" ascii
        $key_2 = "Bro Falls:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Fall Guys:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Granny:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MICROVOLTS:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Maurice:" ascii
        $key_19 = "ONE PIECE:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "RAM:" ascii
        $key_23 = "Shower With Your Dad Simulator 2015:" ascii
        $key_24 = "SuchArt:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}