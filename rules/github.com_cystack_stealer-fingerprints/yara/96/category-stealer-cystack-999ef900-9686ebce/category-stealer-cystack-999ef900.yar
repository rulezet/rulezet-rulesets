rule Category_Stealer_cystack_999ef900
{
    meta:
        family = "Category Stealer"
        fingerprint_id = "cystack_999ef900"

    strings:
        $key_0 = "Build ID:" ascii
        $key_1 = "CPU:" ascii
        $key_2 = "Category:" ascii
        $key_3 = "Computer:" ascii
        $key_4 = "Cores/Threads:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Displays:" ascii
        $key_7 = "GPU:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "IP:" ascii
        $key_10 = "Language:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "OS:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "Timezone:" ascii
        $key_16 = "UTC Time:" ascii
        $key_17 = "Username:" ascii

    condition:
        all of ($key_*)
}