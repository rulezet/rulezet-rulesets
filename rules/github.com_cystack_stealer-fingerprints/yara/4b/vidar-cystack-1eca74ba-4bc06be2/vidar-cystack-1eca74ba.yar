rule Vidar_cystack_1eca74ba
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_1eca74ba"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Auto Cell:" ascii
        $key_2 = "Cities:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "Espresso Tycoon Prologue:" ascii
        $key_9 = "GUID:" ascii
        $key_10 = "HWID:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Path:" ascii
        $key_17 = "Portal 2:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Sandbox:" ascii
        $key_21 = "Threads:" ascii
        $key_22 = "TimeZone:" ascii
        $key_23 = "User Name:" ascii
        $key_24 = "VideoCard:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}