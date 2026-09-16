rule PEiD_00321_BopCrypt_v1_0_
{
    meta:
        description = "[BopCrypt v1.0]"
        ep_only = "true"
    strings:
        $a = {60 BD ?? ?? ?? ?? E8 ?? ?? 00 00}
    condition:
        $a
}