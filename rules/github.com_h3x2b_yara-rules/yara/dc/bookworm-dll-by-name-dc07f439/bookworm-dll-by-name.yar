rule bookworm_dll_by_name : malware
{
    meta:
        author = "@h3x2b <tracker _AT h3x.eu>"
        description = "Match ushata by the name"

    strings:
        $dll01 = "ushata.dll"
        $dll02 = "XecureIO_v20.dll"

    condition:
        any of them 
        and filesize < 10000

}