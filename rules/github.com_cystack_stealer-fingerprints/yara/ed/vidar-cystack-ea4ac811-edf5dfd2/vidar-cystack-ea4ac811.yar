rule Vidar_cystack_ea4ac811
{
    meta:
        family = "Vidar"
        fingerprint_id = "cystack_ea4ac811"

    strings:
        $key_0 = "Cores:" ascii
        $key_1 = "Crash Bandicoot 4:" ascii
        $key_2 = "Grand Theft Auto IV:" ascii
        $key_3 = "Minecraft:" ascii
        $key_4 = "Police Simulator:" ascii
        $key_5 = "Processor:" ascii
        $key_6 = "RAM:" ascii
        $key_7 = "Taxi Life:" ascii
        $key_8 = "Threads:" ascii
        $key_9 = "VideoCard:" ascii

    condition:
        all of ($key_*)
}