rule CSEmojiCountStealer_cystack_fef48703
{
    meta:
        family = "CSEmojiCountStealer"
        fingerprint_id = "cystack_fef48703"

    strings:
        $key_0 = "Antivirus:" ascii
        $key_1 = "Build:" ascii
        $key_2 = "CPU:" ascii
        $key_3 = "City:" ascii
        $key_4 = "Cookies:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Credit Cards:" ascii
        $key_7 = "Current Language:" ascii
        $key_8 = "Discord Tokens:" ascii
        $key_9 = "FileLocation:" ascii
        $key_10 = "Files:" ascii
        $key_11 = "GPU:" ascii
        $key_12 = "HWID:" ascii
        $key_13 = "IP:" ascii
        $key_14 = "ISP:" ascii
        $key_15 = "Is Elevated:" ascii
        $key_16 = "OS:" ascii
        $key_17 = "Passwords:" ascii
        $key_18 = "Postal:" ascii
        $key_19 = "Servers FTP/SSH:" ascii
        $key_20 = "Tagged Cookies:" ascii
        $key_21 = "Tagged URLs:" ascii
        $key_22 = "Tags Cookies:" ascii
        $key_23 = "Tags Passwords:" ascii
        $key_24 = "Timezone:" ascii
        $key_25 = "Username:" ascii
        $key_26 = "Wallets:" ascii

    condition:
        all of ($key_*)
}