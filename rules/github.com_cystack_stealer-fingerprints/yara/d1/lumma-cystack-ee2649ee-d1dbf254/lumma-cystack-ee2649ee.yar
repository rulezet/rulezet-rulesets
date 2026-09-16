rule Lumma_cystack_ee2649ee
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_ee2649ee"

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
        $key_9 = "Hostname:" ascii
        $key_10 = "IP Address:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "LID:" ascii
        $key_13 = "Language:" ascii
        $key_14 = "Local Date:" ascii
        $key_15 = "LummaC2 Build:" ascii
        $key_16 = "NetBIOS:" ascii
        $key_17 = "OS Version:" ascii
        $key_18 = "RAM Size:" ascii
        $key_19 = "Time:" ascii
        $key_20 = "Time Zone:" ascii

    condition:
        all of ($key_*)
}