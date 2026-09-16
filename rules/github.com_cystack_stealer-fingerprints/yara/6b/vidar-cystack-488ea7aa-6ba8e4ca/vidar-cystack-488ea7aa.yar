rule Vidar_cystack_488ea7aa
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_488ea7aa"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Avatar:" ascii
        $key_2 = "Bully:" ascii
        $key_3 = "Castlevania:" ascii
        $key_4 = "Clair Obscur:" ascii
        $key_5 = "Computer Name:" ascii
        $key_6 = "Cores:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Display Resolution:" ascii
        $key_10 = "Dying Light:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "Ghostbusters:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "NARUTO SHIPPUDEN:" ascii
        $key_19 = "NARUTO TO BORUTO:" ascii
        $key_20 = "ONE PIECE:" ascii
        $key_21 = "Path:" ascii
        $key_22 = "Processor:" ascii
        $key_23 = "RAM:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}