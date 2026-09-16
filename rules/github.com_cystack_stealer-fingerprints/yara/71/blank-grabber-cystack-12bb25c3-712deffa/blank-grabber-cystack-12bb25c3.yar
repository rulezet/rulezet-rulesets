rule Blank_Grabber_cystack_12bb25c3
{
    meta:
        family = "Blank Grabber"
        fingerprint_id = "cystack_12bb25c3"

    strings:
        $key_0 = "Autofills:" ascii
        $key_1 = "Blank Grabber got a new victim:" ascii
        $key_2 = "CPU:" ascii
        $key_3 = "Common Files:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Computer OS:" ascii
        $key_6 = "Cookies:" ascii
        $key_7 = "Discord Accounts:" ascii
        $key_8 = "Epic Session:" ascii
        $key_9 = "GPU:" ascii
        $key_10 = "Growtopia Session:" ascii
        $key_11 = "History:" ascii
        $key_12 = "Minecraft Sessions:" ascii
        $key_13 = "Passwords:" ascii
        $key_14 = "Product Key:" ascii
        $key_15 = "Roblox Cookies:" ascii
        $key_16 = "Screenshot:" ascii
        $key_17 = "Steam Session:" ascii
        $key_18 = "System Info:" ascii
        $key_19 = "Total Memory:" ascii
        $key_20 = "UUID:" ascii
        $key_21 = "Uplay Session:" ascii
        $key_22 = "Wallets:" ascii
        $key_23 = "Webcam:" ascii
        $key_24 = "Wifi Passwords:" ascii

    condition:
        all of ($key_*)
}