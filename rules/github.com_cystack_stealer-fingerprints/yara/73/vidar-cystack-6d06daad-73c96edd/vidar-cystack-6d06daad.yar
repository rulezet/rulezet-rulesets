rule Vidar_cystack_6d06daad
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_6d06daad"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Bad Dream:" ascii
        $key_2 = "Black Myth:" ascii
        $key_3 = "Computer Name:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Country:" ascii
        $key_6 = "Date:" ascii
        $key_7 = "Display Resolution:" ascii
        $key_8 = "FIND ALL 2:" ascii
        $key_9 = "FIND ALL 3:" ascii
        $key_10 = "GUID:" ascii
        $key_11 = "HWID:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Keyboard Languages:" ascii
        $key_15 = "Local Time:" ascii
        $key_16 = "MachineID:" ascii
        $key_17 = "Oceanhorn 2:" ascii
        $key_18 = "Path:" ascii
        $key_19 = "Processor:" ascii
        $key_20 = "RAM:" ascii
        $key_21 = "The Stanley Parable:" ascii
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