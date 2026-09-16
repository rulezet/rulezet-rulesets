rule Lumma_cystack_78a2bec1
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_78a2bec1"

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
        $key_13 = "LID:" ascii
        $key_14 = "Language:" ascii
        $key_15 = "Local Date:" ascii
        $key_16 = "LummaC2 Build:" ascii
        $key_17 = "NetBIOS:" ascii
        $key_18 = "OS Version:" ascii
        $key_19 = "RAM Size:" ascii
        $key_20 = "Time:" ascii
        $key_21 = "Time Zone:" ascii
        $key_22 = "User:" ascii

    condition:
        all of ($key_*)
}