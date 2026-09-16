rule CSWmicDumpStealer_snake_case_wmic_dump_system_info_txt
{
    meta:
        family = "CSWmicDumpStealer"
        fingerprint_id = "snake_case_wmic_dump_system_info_txt"

    strings:
        $key_0 = "Ethernet adapter Ethernet:" ascii
        $key_1 = "Ethernet adapter vEthernet (Ethernet):" ascii
        $key_2 = "Ethernet adapter vEthernet (Wi-Fi):" ascii
        $key_3 = "Tunnel adapter 6to4 Adapter:" ascii
        $key_4 = "Wireless LAN adapter Wi-Fi:" ascii

    condition:
        all of ($key_*)
}