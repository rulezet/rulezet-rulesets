rule PEiD_01026_MEW_11_SE_v1_2____Northfox_HCC_
{
    meta:
        description = "[MEW 11 SE v1.2 -> Northfox[HCC]"
        ep_only = "true"
    strings:
        $a = {E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00}
    condition:
        $a
}