rule Vidar_cystack_0eb411db
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_0eb411db"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Country:" ascii
        $key_3 = "Date:" ascii
        $key_4 = "Display Resolution:" ascii
        $key_5 = "GUID:" ascii
        $key_6 = "HWID:" ascii
        $key_7 = "Install Date:" ascii
        $key_8 = "Ip:" ascii
        $key_9 = "Keyboard Languages:" ascii
        $key_10 = "MachineID:" ascii
        $key_11 = "Path:" ascii
        $key_12 = "User Name:" ascii
        $key_13 = "Version:" ascii
        $key_14 = "Windows:" ascii
        $key_15 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}