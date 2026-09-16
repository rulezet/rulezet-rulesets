rule Category_Stealer_cystack_f2e27cfe
{
    meta:
        family = "Category Stealer"
        fingerprint_id = "cystack_f2e27cfe"

    strings:
        $key_0 = "CPU:" ascii
        $key_1 = "Category:" ascii
        $key_2 = "Computer:" ascii
        $key_3 = "Cores/Threads:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Displays:" ascii
        $key_6 = "GPU:" ascii
        $key_7 = "HWID:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "Keyboards:" ascii
        $key_10 = "Language:" ascii
        $key_11 = "Local Time:" ascii
        $key_12 = "OS:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "System:" ascii
        $key_16 = "Timezone:" ascii
        $key_17 = "UTC Time:" ascii
        $key_18 = "Username:" ascii

    condition:
        all of ($key_*)
}