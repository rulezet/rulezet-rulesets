rule PEiD_00138_Armadillo_v1_71_
{
    meta:
        description = "[Armadillo v1.71]"
        ep_only = "false"
    strings:
        $a = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1}
    condition:
        $a
}