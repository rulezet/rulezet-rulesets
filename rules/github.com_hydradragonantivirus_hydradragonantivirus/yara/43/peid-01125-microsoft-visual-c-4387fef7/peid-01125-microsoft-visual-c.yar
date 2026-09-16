rule PEiD_01125_Microsoft_Visual_C___
{
    meta:
        description = "[Microsoft Visual C++]"
        ep_only = "false"
    strings:
        $a = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00}
    condition:
        $a
}