rule Vidar_cystack_e9d927e6
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_e9d927e6"

    strings:
        $key_0 = "AV:" ascii
        $key_1 = "Alien Swarm:" ascii
        $key_2 = "Ancestors:" ascii
        $key_3 = "Call of Duty:" ascii
        $key_4 = "Computer Name:" ascii
        $key_5 = "Cores:" ascii
        $key_6 = "Counter-Strike:" ascii
        $key_7 = "Country:" ascii
        $key_8 = "Date:" ascii
        $key_9 = "Day of Defeat:" ascii
        $key_10 = "Display Resolution:" ascii
        $key_11 = "Entropy:" ascii
        $key_12 = "Fallout:" ascii
        $key_13 = "Feed and Grow:" ascii
        $key_14 = "GUID:" ascii
        $key_15 = "HWID:" ascii
        $key_16 = "Half-Life:" ascii
        $key_17 = "Half-Life 2:" ascii
        $key_18 = "Half-Life Deathmatch:" ascii
        $key_19 = "Halo:" ascii
        $key_20 = "Hand Simulator:" ascii
        $key_21 = "Install Date:" ascii
        $key_22 = "Insurgency:" ascii
        $key_23 = "Ip:" ascii
        $key_24 = "Keyboard Languages:" ascii
        $key_25 = "Local Time:" ascii
        $key_26 = "METAL GEAR SOLID V:" ascii
        $key_27 = "MachineID:" ascii
        $key_28 = "Metro:" ascii
        $key_29 = "Path:" ascii
        $key_30 = "Plague Inc:" ascii
        $key_31 = "Portal:" ascii
        $key_32 = "Portal Stories:" ascii
        $key_33 = "Processor:" ascii
        $key_34 = "RAM:" ascii
        $key_35 = "RISK:" ascii
        $key_36 = "Rebel Inc:" ascii
        $key_37 = "RoboCop:" ascii
        $key_38 = "STALCRAFT:" ascii
        $key_39 = "STAR WARS Jedi:" ascii
        $key_40 = "SUPERHOT:" ascii
        $key_41 = "Star Wars:" ascii
        $key_42 = "The Elder Scrolls V:" ascii
        $key_43 = "Threads:" ascii
        $key_44 = "TimeZone:" ascii
        $key_45 = "Total War:" ascii
        $key_46 = "User Name:" ascii
        $key_47 = "VideoCard:" ascii
        $key_48 = "Windows:" ascii
        $key_49 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}