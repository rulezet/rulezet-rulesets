rule Lumma_russia34_com_lumma_russia_34_bullet
{
    meta:
        family = "Lumma"
        fingerprint_id = "russia34_com_lumma_russia_34_bullet"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Country:" ascii
        $key_2 = "Date:" ascii
        $key_3 = "GUID:" ascii
        $key_4 = "HWID:" ascii
        $key_5 = "Ip:" ascii
        $key_6 = "Lurk in the Dark:" ascii
        $key_7 = "MachineID:" ascii
        $key_8 = "Max Payne 2:" ascii
        $key_9 = "Path:" ascii
        $key_10 = "Processor:" ascii
        $key_11 = "RAM:" ascii
        $key_12 = "Threads:" ascii
        $key_13 = "Version:" ascii
        $key_14 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}