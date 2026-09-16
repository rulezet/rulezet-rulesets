rule Blank_Grabber_cystack_3251e7a5
{
    meta:
        family = "Blank Grabber"
        fingerprint_id = "cystack_3251e7a5"

    strings:
        $key_0 = "Autofills:" ascii
        $key_1 = "CPU:" ascii
        $key_2 = "Cellular Network:" ascii
        $key_3 = "Common Files:" ascii
        $key_4 = "Computer Name:" ascii
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
        $key_19 = "Roblox Cookies:" ascii
        $key_20 = "Screenshot:" ascii
        $key_21 = "Steam Session:" ascii
        $key_22 = "System Info:" ascii
        $key_23 = "Timezone:" ascii
        $key_24 = "Total Memory:" ascii
        $key_25 = "UUID:" ascii
        $key_26 = "Uplay Session:" ascii
        $key_27 = "Wallets:" ascii
        $key_28 = "Webcam:" ascii
        $key_29 = "Wifi Passwords:" ascii

    condition:
        all of ($key_*)
}