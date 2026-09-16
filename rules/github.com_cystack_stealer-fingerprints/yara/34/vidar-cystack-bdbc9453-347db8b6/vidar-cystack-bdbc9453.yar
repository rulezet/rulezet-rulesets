rule Vidar_cystack_bdbc9453
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bdbc9453"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "BloodRayne:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Castlevania:" ascii
        $key_4 = "Clair Obscur:" ascii
        $key_5 = "Computer Name:" ascii
        $key_6 = "Cores:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "DYNASTY WARRIORS:" ascii
        $key_9 = "Date:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "GUID:" ascii
        $key_12 = "Grand Theft Auto:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Hollow Knight:" ascii
        $key_15 = "IP:" ascii
        $key_16 = "Install Date:" ascii
        $key_17 = "Into the Dead:" ascii
        $key_18 = "Keyboard Languages:" ascii
        $key_19 = "Local Time:" ascii
        $key_20 = "MY HERO ACADEMIA:" ascii
        $key_21 = "MachineID:" ascii
        $key_22 = "Path:" ascii
        $key_23 = "Processor:" ascii
        $key_24 = "RAM:" ascii
        $key_25 = "Samurai Jack:" ascii
        $key_26 = "Spider-Man:" ascii
        $key_27 = "Telegram:" ascii
        $key_28 = "Threads:" ascii
        $key_29 = "TimeZone:" ascii
        $key_30 = "User Name:" ascii
        $key_31 = "Version:" ascii
        $key_32 = "VideoCard:" ascii
        $key_33 = "Windows:" ascii
        $key_34 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}