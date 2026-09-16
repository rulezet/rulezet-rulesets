rule Vidar_cystack_fddea8c8
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_fddea8c8"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Computer Name:" ascii
        $key_2 = "Cores:" ascii
        $key_3 = "Country:" ascii
        $key_4 = "Date:" ascii
        $key_5 = "Display Resolution:" ascii
        $key_6 = "Enotria:" ascii
        $key_7 = "Far Cry:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Ghost Recon:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Kena:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Prince of Persia:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Resident Evil 7:" ascii
        $key_22 = "Sekiro:" ascii
        $key_23 = "TDPA:" ascii
        $key_24 = "The Last of Us:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "Version:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "WireGuard Installer:" ascii
        $key_32 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}