rule Vidar_cystack_15786a42
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_15786a42"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Borderlands:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Darksiders:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "God Eater:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Sekiro:" ascii
        $key_21 = "Serious Sam 3:" ascii
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