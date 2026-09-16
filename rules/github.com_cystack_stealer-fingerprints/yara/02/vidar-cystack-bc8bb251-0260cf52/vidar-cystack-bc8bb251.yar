rule Vidar_cystack_bc8bb251
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_bc8bb251"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires III:" ascii
        $key_2 = "Brothers in Arms:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Counter-Strike:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Half-Life:" ascii
        $key_12 = "Half-Life 2:" ascii
        $key_13 = "Halo:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "PAYDAY:" ascii
        $key_20 = "Path:" ascii
        $key_21 = "Processor:" ascii
        $key_22 = "Project Reality:" ascii
        $key_23 = "RAM:" ascii
        $key_24 = "Serious Sam HD:" ascii
        $key_25 = "Threads:" ascii
        $key_26 = "TimeZone:" ascii
        $key_27 = "User Name:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}