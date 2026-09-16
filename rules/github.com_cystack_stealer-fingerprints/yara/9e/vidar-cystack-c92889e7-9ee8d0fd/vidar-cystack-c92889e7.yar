rule Vidar_cystack_c92889e7
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c92889e7"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "Date:" ascii
        $key_2 = "GUID:" ascii
        $key_3 = "HWID:" ascii
        $key_4 = "Ip:" ascii
        $key_5 = "MachineID:" ascii
        $key_6 = "Path:" ascii
        $key_7 = "Version:" ascii

    condition:
        all of ($key_*)
}