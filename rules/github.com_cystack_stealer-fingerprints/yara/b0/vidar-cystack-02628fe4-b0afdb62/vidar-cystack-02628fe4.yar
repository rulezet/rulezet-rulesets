rule Vidar_cystack_02628fe4
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_02628fe4"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "BLACK CLOVER:" ascii
        $key_2 = "Batman:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Counter-Strike:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "DRAGON BALL Z:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Digimon Story Cyber Sleuth:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "HWID:" ascii
        $key_13 = "Install Date:" ascii
        $key_14 = "Ip:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Metal Slug:" ascii
        $key_19 = "NARUTO SHIPPUDEN:" ascii
        $key_20 = "NARUTO TO BORUTO:" ascii
        $key_21 = "ONE PIECE:" ascii
        $key_22 = "ONE PUNCH MAN:" ascii
        $key_23 = "PUBG:" ascii
        $key_24 = "Path:" ascii
        $key_25 = "Processor:" ascii
        $key_26 = "RAM:" ascii
        $key_27 = "Resident Evil Re:" ascii
        $key_28 = "Seal:" ascii
        $key_29 = "The Witcher 3:" ascii
        $key_30 = "Threads:" ascii
        $key_31 = "TimeZone:" ascii
        $key_32 = "User Name:" ascii
        $key_33 = "Version:" ascii
        $key_34 = "VideoCard:" ascii
        $key_35 = "Warbands:" ascii
        $key_36 = "Windows:" ascii
        $key_37 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}