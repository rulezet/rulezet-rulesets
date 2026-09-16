rule Lumma_cystack_67f302a7
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_67f302a7"

    strings:
        $key_0 = "CPU Cores:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "CPU Threads:" ascii
        $key_3 = "CPU Vendor:" ascii
        $key_4 = "Computer:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Display resolution:" ascii
        $key_7 = "Domain:" ascii
        $key_8 = "Elevated:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Hostname:" ascii
        $key_11 = "IP Address:" ascii
        $key_12 = "LID:" ascii
        $key_13 = "Language:" ascii
        $key_14 = "NetBIOS:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "RAM Size:" ascii
        $key_17 = "Time:" ascii
        $key_18 = "Time Zone:" ascii
        $key_19 = "User:" ascii

    condition:
        all of ($key_*)
}