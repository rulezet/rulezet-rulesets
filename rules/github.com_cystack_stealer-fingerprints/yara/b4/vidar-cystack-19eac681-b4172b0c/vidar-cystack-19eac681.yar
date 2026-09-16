rule Vidar_cystack_19eac681
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_19eac681"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bully:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Contraband Police:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "GUID:" ascii
        $key_9 = "Grand Theft Auto IV:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Holdfast:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "STAR WARS Jedi:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "Version:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}