rule Vidar_cystack_5ea4c029
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_5ea4c029"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Anarchy:" ascii
        $key_2 = "Brothers in Arms:" ascii
        $key_3 = "Call of Duty:" ascii
        $key_4 = "Cores:" ascii
        $key_5 = "Counter-Strike:" ascii
        $key_6 = "Country:" ascii
        $key_7 = "Date:" ascii
        $key_8 = "Display Resolution:" ascii
        $key_9 = "Frontline 1942:" ascii
        $key_10 = "Gemini:" ascii
        $key_11 = "Grime:" ascii
        $key_12 = "Install Date:" ascii
        $key_13 = "Ip:" ascii
        $key_14 = "Judge Dredd:" ascii
        $key_15 = "Keyboard Languages:" ascii
        $key_16 = "Local Time:" ascii
        $key_17 = "Processor:" ascii
        $key_18 = "RAM:" ascii
        $key_19 = "The Haunted:" ascii
        $key_20 = "Threads:" ascii
        $key_21 = "TimeZone:" ascii
        $key_22 = "User Name:" ascii
        $key_23 = "VideoCard:" ascii
        $key_24 = "Warhammer:" ascii
        $key_25 = "Windows:" ascii
        $key_26 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}