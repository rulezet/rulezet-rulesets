rule PEiD_01025_Mew_11_SE_v1_2__Eng_____Northfox_
{
    meta:
        description = "[Mew 11 SE v1.2 (Eng) -> Northfox]"
        ep_only = "true"
    strings:
        $a = {E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C}
    condition:
        $a
}