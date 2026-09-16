rule PEiD_01410_Obsidium_V1_3_0_0____Obsidium_Software_
{
    meta:
        description = "[Obsidium V1.3.0.0 -> Obsidium Software]"
        ep_only = "true"
    strings:
        $a = {EB 04 ?? ?? ?? ?? E8 ?? 00 00 00}
    condition:
        $a
}