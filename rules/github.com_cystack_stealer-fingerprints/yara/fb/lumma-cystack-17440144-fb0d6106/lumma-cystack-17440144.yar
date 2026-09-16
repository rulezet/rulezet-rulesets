rule Lumma_cystack_17440144
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_17440144"

    strings:
        $key_0 = "CPU Cores:" ascii
        $key_1 = "CPU Name:" ascii
        $key_2 = "CPU Threads:" ascii
        $key_3 = "CPU Vendor:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Display resolution:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "Hostname:" ascii
        $key_8 = "IP Address:" ascii
        $key_9 = "LID:" ascii
        $key_10 = "Language:" ascii
        $key_11 = "NetBIOS:" ascii
        $key_12 = "OS Version:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "RAM Size:" ascii
        $key_15 = "Time:" ascii
        $key_16 = "User:" ascii

    condition:
        all of ($key_*)
}