rule Vidar_cystack_d46279cc
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_d46279cc"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Agatha Christie - Hercule Poirot:" ascii
        $key_2 = "Batman:" ascii
        $key_3 = "Broken Sword 4:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Hero-U:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Irony Curtain:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "MachineID:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "Scott Whiskers in:" ascii
        $key_22 = "The Journey Down:" ascii
        $key_23 = "The Last Door:" ascii
        $key_24 = "Threads:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "Version:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Windows:" ascii
        $key_30 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}