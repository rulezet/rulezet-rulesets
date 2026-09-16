rule PEiD_02508_VMProtect_v1_25_____PolyTech_
{
    meta:
        description = "[VMProtect v1.25 --> PolyTech]"
        ep_only = "true"
    strings:
        $a = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06}
    condition:
        $a
}