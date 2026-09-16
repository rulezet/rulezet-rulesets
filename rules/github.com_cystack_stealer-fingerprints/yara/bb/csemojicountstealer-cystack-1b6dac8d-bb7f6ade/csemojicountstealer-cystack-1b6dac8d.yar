rule CSEmojiCountStealer_cystack_1b6dac8d
{
    meta:
        family = "CSEmojiCountStealer"
        fingerprint_id = "cystack_1b6dac8d"

    strings:
        $key_0 = "Antivirus:" ascii
        $key_1 = "CPU:" ascii
        $key_2 = "City:" ascii
        $key_3 = "Cookies:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Credit Cards:" ascii
        $key_6 = "Current Language:" ascii
        $key_7 = "FileLocation:" ascii
        $key_8 = "Files:" ascii
        $key_9 = "GPU:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "IP:" ascii
        $key_12 = "ISP:" ascii
        $key_13 = "Is Elevated:" ascii
        $key_14 = "OS:" ascii
        $key_15 = "Passwords:" ascii
        $key_16 = "Postal:" ascii
        $key_17 = "Timezone:" ascii
        $key_18 = "Wallets:" ascii

    condition:
        all of ($key_*)
}