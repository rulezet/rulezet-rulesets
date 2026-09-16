rule PEiD_01060_Microsoft_Visual_C____Basic__NET_
{
    meta:
        description = "[Microsoft Visual C# / Basic .NET]"
        ep_only = "true"
    strings:
        $a = {FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
    condition:
        $a
}