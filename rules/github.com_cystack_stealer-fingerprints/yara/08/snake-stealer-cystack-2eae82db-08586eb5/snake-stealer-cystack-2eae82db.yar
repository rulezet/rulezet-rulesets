rule Snake_Stealer_cystack_2eae82db
{
    meta:
        family = "Snake Stealer"
        fingerprint_id = "cystack_2eae82db"

    strings:
        $key_0 = "Adapter:" ascii
        $key_1 = "Build:" ascii
        $key_2 = "CPU:" ascii
        $key_3 = "CPU Cores:" ascii
        $key_4 = "CPU Threads:" ascii
        $key_5 = "Computer Name:" ascii
        $key_6 = "Current Time:" ascii
        $key_7 = "GPU(s):" ascii
        $key_8 = "OS Version:" ascii
        $key_9 = "Processor Count:" ascii
        $key_10 = "Product Name:" ascii
        $key_11 = "SearchIndexer (PID:" ascii
        $key_12 = "Sysmon64 (PID:" ascii
        $key_13 = "System Directory:" ascii
        $key_14 = "Time Zone:" ascii
        $key_15 = "Total RAM:" ascii
        $key_16 = "Uptime:" ascii
        $key_17 = "User Domain:" ascii
        $key_18 = "User Name:" ascii
        $key_19 = "Version:" ascii
        $key_20 = "WinSAT (PID:" ascii
        $key_21 = "WmiPrvSE (PID:" ascii

    condition:
        all of ($key_*)
}