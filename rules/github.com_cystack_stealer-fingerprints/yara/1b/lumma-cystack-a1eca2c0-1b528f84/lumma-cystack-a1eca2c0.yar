rule Lumma_cystack_a1eca2c0
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_a1eca2c0"

    strings:
        $key_0 = "CPU Cores:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "CPU Threads:" ascii
        $key_3 = "CPU Vendor:" ascii
        $key_4 = "Computer:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Display resolution:" ascii
        $key_7 = "Elevated:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP Address:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Language:" ascii
        $key_12 = "Local Date:" ascii
        $key_13 = "LummaC2 Build:" ascii
        $key_14 = "NetBIOS:" ascii
        $key_15 = "OS Version:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "RAM Size:" ascii
        $key_18 = "Time:" ascii
        $key_19 = "Time Zone:" ascii
        $key_20 = "User:" ascii

    condition:
        all of ($key_*)
}