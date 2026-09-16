rule Blank_Grabber_cystack_531d6bd4
{
    meta:
        family = "Blank Grabber"
        fingerprint_id = "cystack_531d6bd4"

    strings:
        $key_0 = "Autofills:" ascii
        $key_1 = "Blank Grabber got a new victim:" ascii
        $key_2 = "CPU:" ascii
        $key_3 = "Cellular Network:" ascii
        $key_4 = "Common Files:" ascii
        $key_5 = "Computer Name:" ascii
        $key_6 = "Computer OS:" ascii
        $key_7 = "Cookies:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Discord Accounts:" ascii
        $key_10 = "Epic Session:" ascii
        $key_11 = "GPU:" ascii
        $key_12 = "Growtopia Session:" ascii
        $key_13 = "History:" ascii
        $key_14 = "IP:" ascii
        $key_15 = "Minecraft Sessions:" ascii
        $key_16 = "Passwords:" ascii
        $key_17 = "Product Key:" ascii
        $key_18 = "Proxy/VPN:" ascii
        $key_19 = "Region:" ascii
        $key_20 = "Reverse DNS:" ascii
        $key_21 = "Roblox Cookies:" ascii
        $key_22 = "Screenshot:" ascii
        $key_23 = "Steam Session:" ascii
        $key_24 = "System Info:" ascii
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