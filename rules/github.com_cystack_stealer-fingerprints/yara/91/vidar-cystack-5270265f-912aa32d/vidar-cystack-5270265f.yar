rule Vidar_cystack_5270265f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5270265f"

    strings:
        $key_0 = "Country:" ascii
        $key_1 = "Date:" ascii
        $key_2 = "GUID:" ascii
        $key_3 = "Ip:" ascii
        $key_4 = "MachineID:" ascii

    condition:
        all of ($key_*)
}