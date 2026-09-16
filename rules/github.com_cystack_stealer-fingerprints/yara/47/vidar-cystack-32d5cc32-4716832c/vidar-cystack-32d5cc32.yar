rule Vidar_cystack_32d5cc32
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_32d5cc32"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Call of Duty:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "Far Cry:" ascii
        $key_8 = "GTA:" ascii
        $key_9 = "GTA IV:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "Ghost Recon:" ascii
        $key_12 = "God of War:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Horizon:" ascii
        $key_15 = "Install Date:" ascii
        $key_16 = "Ip:" ascii
        $key_17 = "Keyboard Languages:" ascii
        $key_18 = "Local Time:" ascii
        $key_19 = "MachineID:" ascii
        $key_20 = "Mafia II:" ascii
        $key_21 = "Max Payne 3:" ascii
        $key_22 = "Path:" ascii
        $key_23 = "Processor:" ascii
        $key_24 = "RAM:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "Version:" ascii
        $key_29 = "VideoCard:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}