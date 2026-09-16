rule Lumma_cystack_8176e468
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_8176e468"

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
        $key_12 = "Install Date:" ascii
        $key_13 = "Language:" ascii
        $key_14 = "Local Date:" ascii
        $key_15 = "LummaC2 Build:" ascii
        $key_16 = "NetBIOS:" ascii
        $key_17 = "OS Version:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "RAM Size:" ascii
        $key_20 = "Time:" ascii
        $key_21 = "Time Zone:" ascii
        $key_22 = "User:" ascii

    condition:
        all of ($key_*)
}