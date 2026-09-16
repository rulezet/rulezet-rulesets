rule Lumma_cystack_9329a751
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_9329a751"

    strings:
        $key_0 = "CPU Cores:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "CPU Threads:" ascii
        $key_3 = "CPU Vendor:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display resolution:" ascii
        $key_6 = "Elevated:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "Hostname:" ascii
        $key_9 = "IP Address:" ascii
        $key_10 = "Install Date:" ascii
        $key_11 = "Language:" ascii
        $key_12 = "Local Date:" ascii
        $key_13 = "LummaC2 Build:" ascii
        $key_14 = "OS Version:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "RAM Size:" ascii
        $key_17 = "Time:" ascii
        $key_18 = "Time Zone:" ascii
        $key_19 = "User:" ascii

    condition:
        all of ($key_*)
}