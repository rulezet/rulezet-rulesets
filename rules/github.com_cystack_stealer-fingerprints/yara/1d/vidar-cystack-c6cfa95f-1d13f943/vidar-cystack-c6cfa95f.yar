rule Vidar_cystack_c6cfa95f
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_c6cfa95f"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bob Esponja:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "HWID:" ascii
        $key_9 = "Hollow Knight:" ascii
        $key_10 = "INAZUMA ELEVEN:" ascii
        $key_11 = "IP:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "PICO PARK:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Taxi Life:" ascii
        $key_21 = "Telegram:" ascii
        $key_22 = "Threads:" ascii
        $key_23 = "TimeZone:" ascii
        $key_24 = "User Name:" ascii
        $key_25 = "Version:" ascii
        $key_26 = "VideoCard:" ascii
        $key_27 = "Windows:" ascii
        $key_28 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}