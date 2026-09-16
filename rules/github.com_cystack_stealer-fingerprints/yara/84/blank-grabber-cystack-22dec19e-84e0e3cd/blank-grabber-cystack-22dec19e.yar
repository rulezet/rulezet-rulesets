rule Blank_Grabber_cystack_22dec19e
{
    meta:
        family = "Blank Grabber"
        fingerprint_id = "cystack_22dec19e"

    strings:
        $key_0 = "Autofills:" ascii
        $key_1 = "Blank Grabber got a new victim:" ascii
        $key_2 = "CPU:" ascii
        $key_3 = "Cellular Network:" ascii
        $key_4 = "Common Files:" ascii
        $key_5 = "Computer OS:" ascii
        $key_6 = "Cookies:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "Discord Accounts:" ascii
        $key_9 = "Epic Session:" ascii
        $key_10 = "GPU:" ascii
        $key_11 = "Growtopia Session:" ascii
        $key_12 = "History:" ascii
        $key_13 = "IP:" ascii
        $key_14 = "Minecraft Sessions:" ascii
        $key_15 = "Passwords:" ascii
        $key_16 = "Product Key:" ascii
        $key_17 = "Proxy/VPN:" ascii
        $key_18 = "Region:" ascii
        $key_19 = "Reverse DNS:" ascii
        $key_20 = "Roblox Cookies:" ascii
        $key_21 = "Screenshot:" ascii
        $key_22 = "Steam Session:" ascii
        $key_23 = "System Info:" ascii
        $key_24 = "Telegram Sessions:" ascii
        $key_25 = "Timezone:" ascii
        $key_26 = "Total Memory:" ascii
        $key_27 = "UUID:" ascii
        $key_28 = "Uplay Session:" ascii
        $key_29 = "Wallets:" ascii
        $key_30 = "Webcam:" ascii
        $key_31 = "Wifi Passwords:" ascii

    condition:
        all of ($key_*)
}