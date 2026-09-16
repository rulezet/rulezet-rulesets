rule DCRat_cystack_7508f5a5
{
    meta:
        family = "DCRat"
        fingerprint_id = "cystack_7508f5a5"

    strings:
        $key_0 = "Antivirus:" ascii
        $key_1 = "BIOS:" ascii
        $key_2 = "CPU Name:" ascii
        $key_3 = "City:" ascii
        $key_4 = "Country code:" ascii
        $key_5 = "Firewall:" ascii
        $key_6 = "Framework Version:" ascii
        $key_7 = "GPU Name:" ascii
        $key_8 = "IP:" ascii
        $key_9 = "LANIP:" ascii
        $key_10 = "Location:" ascii
        $key_11 = "Motherboard:" ascii
        $key_12 = "PC Name:" ascii
        $key_13 = "Path:" ascii
        $key_14 = "RAM:" ascii
        $key_15 = "Screens:" ascii
        $key_16 = "User Name:" ascii
        $key_17 = "Windows:" ascii

    condition:
        all of ($key_*)
}