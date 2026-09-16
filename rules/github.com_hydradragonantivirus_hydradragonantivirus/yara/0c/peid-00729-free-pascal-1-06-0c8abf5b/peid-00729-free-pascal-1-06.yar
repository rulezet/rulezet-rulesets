rule PEiD_00729_Free_Pascal_1_06_
{
    meta:
        description = "[Free Pascal 1.06]"
        ep_only = "false"
    strings:
        $a = {C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00}
    condition:
        $a
}