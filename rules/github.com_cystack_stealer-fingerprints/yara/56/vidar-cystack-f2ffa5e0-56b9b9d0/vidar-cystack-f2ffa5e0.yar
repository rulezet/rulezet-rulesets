rule Vidar_cystack_f2ffa5e0
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_f2ffa5e0"

    strings:
        $key_0 = "Bendy and the Ink Machine:" ascii
        $key_1 = "Build:" ascii
        $key_2 = "CPU Count:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cult of the Lamb:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Language:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "IP:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "Location:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Path:" ascii
        $key_16 = "Processor:" ascii
        $key_17 = "RAM:" ascii
        $key_18 = "TimeZone:" ascii
        $key_19 = "User Name:" ascii
        $key_20 = "Version:" ascii
        $key_21 = "Windows:" ascii
        $key_22 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}