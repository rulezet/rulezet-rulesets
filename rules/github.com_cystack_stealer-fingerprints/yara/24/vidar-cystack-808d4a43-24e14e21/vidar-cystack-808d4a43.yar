rule Vidar_cystack_808d4a43
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_808d4a43"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Enotria:" ascii
        $key_8 = "Far Cry:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "Ghost Recon:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Kena:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Prince of Persia:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Resident Evil 7:" ascii
        $key_23 = "Sekiro:" ascii
        $key_24 = "TDPA:" ascii
        $key_25 = "The Last of Us:" ascii
        $key_26 = "Threads:" ascii
        $key_27 = "TimeZone:" ascii
        $key_28 = "User Name:" ascii
        $key_29 = "Version:" ascii
        $key_30 = "VideoCard:" ascii
        $key_31 = "WH40K:" ascii
        $key_32 = "Windows:" ascii
        $key_33 = "WireGuard Installer:" ascii
        $key_34 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}