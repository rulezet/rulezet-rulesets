rule Vidar_cystack_b0045fa0
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_b0045fa0"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Age of Empires II:" ascii
        $key_2 = "Age of Empires III:" ascii
        $key_3 = "Age of Empires IV:" ascii
        $key_4 = "Age of Mythology:" ascii
        $key_5 = "Call of Duty:" ascii
        $key_6 = "Computer Name:" ascii
        $key_7 = "Cores:" ascii
        $key_8 = "Counter-Strike:" ascii
        $key_9 = "Country:" ascii
        $key_10 = "Date:" ascii
        $key_11 = "Display Resolution:" ascii
        $key_12 = "GUID:" ascii
        $key_13 = "HWID:" ascii
        $key_14 = "Install Date:" ascii
        $key_15 = "Ip:" ascii
        $key_16 = "Keyboard Languages:" ascii
        $key_17 = "Local Time:" ascii
        $key_18 = "MachineID:" ascii
        $key_19 = "Path:" ascii
        $key_20 = "Processor:" ascii
        $key_21 = "RAM:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "VideoCard:" ascii
        $key_26 = "Windows:" ascii
        $key_27 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}