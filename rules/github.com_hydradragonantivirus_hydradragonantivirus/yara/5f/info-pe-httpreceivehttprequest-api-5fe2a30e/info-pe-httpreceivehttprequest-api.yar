rule INFO_PE_HttpReceiveHttpRequest_API
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-18"
        version = "1.0"
        description = "track executable files that reference HttpReceiveHttpRequest, which will be used to handle inbound HTTP requests"
        DaysofYARA = "18/100"

    strings:
        $ = "HttpReceiveHttpRequest" nocase ascii wide
    condition:
        uint16be(0) == 0x4d5a and all of them
}