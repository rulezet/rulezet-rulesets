rule Vidar_cystack_553355c7
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_553355c7"

    strings:
        $key_0 = "ARK:" ascii
        $key_1 = "AV:" ascii
        $key_2 = "Computer Name:" ascii
        $key_3 = "Cores:" ascii
        $key_4 = "Country:" ascii
        $key_5 = "Date:" ascii
        $key_6 = "Display Resolution:" ascii
        $key_7 = "GUID:" ascii
        $key_8 = "Grand Theft Auto IV:" ascii
        $key_9 = "HWID:" ascii
        $key_10 = "Hello Neighbor:" ascii
        $key_11 = "Install Date:" ascii
        $key_12 = "Ip:" ascii
        $key_13 = "Keyboard Languages:" ascii
        $key_14 = "Local Time:" ascii
        $key_15 = "MachineID:" ascii
        $key_16 = "Parking Tycoon:" ascii
        $key_17 = "Path:" ascii
        $key_18 = "Processor:" ascii
        $key_19 = "RAM:" ascii
        $key_20 = "Serious Sam 3:" ascii
        $key_21 = "Serious Sam HD:" ascii
        $key_22 = "The Elder Scrolls IV:" ascii
        $key_23 = "Threads:" ascii
        $key_24 = "Ticket to Ride:" ascii
        $key_25 = "TimeZone:" ascii
        $key_26 = "User Name:" ascii
        $key_27 = "VideoCard:" ascii
        $key_28 = "Windows:" ascii
        $key_29 = "Work Dir:" ascii

    condition:
        all of ($key_*)
}