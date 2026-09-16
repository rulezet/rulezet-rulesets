rule INFO_PE_WSARecv_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-17"
        version = "1.0"
        description = "track executable files that reference WSARecv, which may be hooked for passive listening"
        DaysofYARA = "17/100"

    strings:
        $ = "WSARecv" ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}