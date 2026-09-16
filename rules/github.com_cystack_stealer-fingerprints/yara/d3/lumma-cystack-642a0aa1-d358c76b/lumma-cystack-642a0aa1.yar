rule Lumma_cystack_642a0aa1
{
    meta:
        family = "Lumma"
        fingerprint_id = "cystack_642a0aa1"

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
        $key_11 = "LID:" ascii
        $key_12 = "Language:" ascii
        $key_13 = "NetBIOS:" ascii
        $key_14 = "OS Version:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "RAM Size:" ascii
        $key_17 = "Time:" ascii
        $key_18 = "User:" ascii

    condition:
        all of ($key_*)
}