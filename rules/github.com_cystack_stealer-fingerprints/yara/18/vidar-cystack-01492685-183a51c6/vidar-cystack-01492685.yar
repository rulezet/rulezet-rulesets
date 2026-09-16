rule Vidar_cystack_01492685
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_01492685"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Mythology:" ascii
        $key_2 = "Call of Duty:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Dying Light 2:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "Lost Lullabies:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Parking Tycoon:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "State of Decay:" ascii
        $key_22 = "The Elder Scrolls V:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "TimeZone:" ascii
        $key_25 = "Unnatural:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "Version:" ascii
        $key_28 = "VideoCard:" ascii
        $key_29 = "Warhammer:" ascii
        $key_30 = "Windows:" ascii
        $key_31 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}