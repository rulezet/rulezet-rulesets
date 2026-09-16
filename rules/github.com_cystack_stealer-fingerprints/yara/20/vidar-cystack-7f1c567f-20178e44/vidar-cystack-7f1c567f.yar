rule Vidar_cystack_7f1c567f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_7f1c567f"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Amnesia:" ascii
        $key_2 = "Batman:" ascii
        $key_3 = "Beyond:" ascii
        $key_4 = "Bully:" ascii
        $key_5 = "Castlevania:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "HWID:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "NARUTO SHIPPUDEN:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "Version:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}