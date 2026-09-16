rule Vidar_cystack_cc26a471
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_cc26a471"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "GUID:" ascii
        $key_5 = "HWID:" ascii
        $key_6 = "Install Date:" ascii
        $key_7 = "Ip:" ascii
        $key_8 = "MachineID:" ascii
        $key_9 = "Path:" ascii
        $key_10 = "Version:" ascii
        $key_11 = "Windows:" ascii
        $key_12 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}