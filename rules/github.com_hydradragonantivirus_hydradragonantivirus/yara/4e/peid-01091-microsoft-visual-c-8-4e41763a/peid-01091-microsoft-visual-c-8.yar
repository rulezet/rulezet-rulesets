import "pe"
rule PEiD_01091_Microsoft_Visual_C___8_
{
    meta:
        description = "[Microsoft Visual C++ 8]"
        ep_only = "true"
    strings:
        $a = {E8 ?? ?? 00 00 E9 ?? ?? FF FF}
    condition:
        $a at pe.entry_point
}