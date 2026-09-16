rule Blank_Grabber_cystack_30a7fa5c
{
    meta:
        family = "Blank Grabber"
        fingerprint_id = "cystack_30a7fa5c"

    strings:
        $key_0 = "Autofills:" ascii
        $key_1 = "CPU:" ascii
        $key_2 = "Common Files:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Computer OS:" ascii
        $key_5 = "Cookies:" ascii
        $key_6 = "Discord Accounts:" ascii
        $key_7 = "Epic Session:" ascii
        $key_8 = "GPU:" ascii
        $key_9 = "Growtopia Session:" ascii
        $key_10 = "History:" ascii
        $key_11 = "Minecraft Sessions:" ascii
        $key_12 = "Passwords:" ascii
        $key_13 = "Product Key:" ascii
        $key_14 = "Roblox Cookies:" ascii
        $key_15 = "Screenshot:" ascii
        $key_16 = "Steam Session:" ascii
        $key_17 = "System Info:" ascii
        $key_18 = "Telegram Sessions:" ascii
        $key_19 = "Total Memory:" ascii
        $key_20 = "UUID:" ascii
        $key_21 = "Uplay Session:" ascii
        $key_22 = "Wallets:" ascii
        $key_23 = "Webcam:" ascii
        $key_24 = "Wifi Passwords:" ascii

    condition:
        all of ($key_*)
}