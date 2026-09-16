rule Lumma_cystack_4d2e6c3b
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_4d2e6c3b"

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
        $key_10 = "LID:" ascii
        $key_11 = "Language:" ascii
        $key_12 = "NetBIOS:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "RAM Size:" ascii
        $key_15 = "Time:" ascii
        $key_16 = "User:" ascii

    condition:
        all of ($key_*)
}