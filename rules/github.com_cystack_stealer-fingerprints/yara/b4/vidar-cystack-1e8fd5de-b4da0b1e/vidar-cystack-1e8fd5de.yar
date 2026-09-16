rule Vidar_cystack_1e8fd5de
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1e8fd5de"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bloodstained:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Install Date:" ascii
        $key_10 = "Ip:" ascii
        $key_11 = "Jacksmith:" ascii
        $key_12 = "Keyboard Languages:" ascii
        $key_13 = "Local Time:" ascii
        $key_14 = "MachineID:" ascii
        $key_15 = "Operation Lovecraft:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "SCP:" ascii
        $key_20 = "Stick Fight:" ascii
        $key_21 = "Taimanin Asagi 1:" ascii
        $key_22 = "Taimanin Yukikaze 1:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "User Name:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii
        $key_29 = "Zoey:" ascii

    condition:
        all of ($key_*)
}