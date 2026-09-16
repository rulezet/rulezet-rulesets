rule Lumma_cystack_7fc55edb
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_7fc55edb"

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
        $key_12 = "Language:" ascii
        $key_13 = "Local Date:" ascii
        $key_14 = "LummaC2 Build:" ascii
        $key_15 = "NetBIOS:" ascii
        $key_16 = "OS Version:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "RAM Size:" ascii
        $key_19 = "Time Zone:" ascii
        $key_20 = "User:" ascii

    condition:
        all of ($key_*)
}