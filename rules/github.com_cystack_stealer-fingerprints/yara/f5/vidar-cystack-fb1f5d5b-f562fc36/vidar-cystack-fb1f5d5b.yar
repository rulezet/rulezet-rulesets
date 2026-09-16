rule Vidar_cystack_fb1f5d5b
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_fb1f5d5b"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Batman:" ascii
        $key_3 = "Call of Duty:" ascii
        $key_4 = "Cobra Kai:" ascii
        $key_5 = "Cobra Kai 2:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Country:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "ENDER MAGNOLIA:" ascii
        $key_12 = "GUID:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Microsoft Flight Simulator X:" ascii
        $key_20 = "Motor Town:" ascii
        $key_21 = "NARUTO SHIPPUDEN:" ascii
        $key_22 = "New World:" ascii
        $key_23 = "Night Drive:" ascii
        $key_24 = "ONLY UP:" ascii
        $key_25 = "Only Up:" ascii
        $key_26 = "PAYDAY:" ascii
        $key_27 = "Path:" ascii
        $key_28 = "Processor:" ascii
        $key_29 = "RAM:" ascii
        $key_30 = "Threads:" ascii
        $key_31 = "TimeZone:" ascii
        $key_32 = "User Name:" ascii
        $key_33 = "VideoCard:" ascii
        $key_34 = "Windows:" ascii
        $key_35 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}