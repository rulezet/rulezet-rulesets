rule INFO_PE_Port_Slash_Combo
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that include small strings that might indicate port usage "
        DaysofYARA = "17/100"

    strings:
        $ = ":80/" ascii wide
        $ = ":443/" ascii wide
        $regex = /\:[0-9]{2,4}\//ascii wide
    condition:
        uint16be(0) == 0x4d5a and any of them
}