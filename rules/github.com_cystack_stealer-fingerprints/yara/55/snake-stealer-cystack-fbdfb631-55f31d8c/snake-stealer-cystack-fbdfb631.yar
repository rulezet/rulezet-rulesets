rule Snake_Stealer_cystack_fbdfb631
{
    meta:
        family = "Snake Stealer"
        fingerprint_id = "cystack_fbdfb631"

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
        $key_9 = "OSPPSVC (PID:" ascii
        $key_10 = "Processor Count:" ascii
        $key_11 = "Product Name:" ascii
        $key_12 = "SearchIndexer (PID:" ascii
        $key_13 = "Sysmon64 (PID:" ascii
        $key_14 = "System Directory:" ascii
        $key_15 = "Time Zone:" ascii
        $key_16 = "Total RAM:" ascii
        $key_17 = "Uptime:" ascii
        $key_18 = "User Domain:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "Version:" ascii
        $key_21 = "WinSAT (PID:" ascii
        $key_22 = "WmiPrvSE (PID:" ascii

    condition:
        all of ($key_*)
}