rule Vidar_cystack_1c4ef15e
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1c4ef15e"

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
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "NARUTO SHIPPUDEN:" ascii
        $key_20 = "NARUTO TO BORUTO:" ascii
        $key_21 = "ONE PIECE:" ascii
        $key_22 = "Path:" ascii
        $key_23 = "Processor:" ascii
        $key_24 = "RAM:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}