rule Vidar_cystack_698261b6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_698261b6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Keyboard Languages:" ascii
        $key_12 = "Local Time:" ascii
        $key_13 = "MachineID:" ascii
        $key_14 = "NFS:" ascii
        $key_15 = "Need for Speed:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "Sekiro:" ascii
        $key_20 = "The Legend of Zelda:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "Tomb Raider:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "Version:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "WireGuard Installer:" ascii
        $key_29 = "Work Dir:" ascii
        $key_30 = "World War Z:" ascii

    condition:
        all of ($key_*)
}