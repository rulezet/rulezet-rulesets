rule Lumma_cystack_a33378ed
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_a33378ed"

    strings:
        $key_0 = "CPU Cores:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "CPU Threads:" ascii
        $key_3 = "CPU Vendor:" ascii
        $key_4 = "Computer:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Display resolution:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "Hostname:" ascii
        $key_9 = "IP Address:" ascii
        $key_10 = "LID:" ascii
        $key_11 = "Language:" ascii
        $key_12 = "LummaC2 Build:" ascii
        $key_13 = "NetBIOS:" ascii
        $key_14 = "RAM Size:" ascii
        $key_15 = "Time:" ascii

    condition:
        all of ($key_*)
}