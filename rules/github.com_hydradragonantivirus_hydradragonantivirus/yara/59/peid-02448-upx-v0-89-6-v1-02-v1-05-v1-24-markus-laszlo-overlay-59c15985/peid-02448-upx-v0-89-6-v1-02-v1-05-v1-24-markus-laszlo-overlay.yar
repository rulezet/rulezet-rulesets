rule PEiD_02448_UPX_v0_89_6___v1_02___v1_05__v1_24____Markus___Laszlo__overlay__
{
    meta:
        description = "[UPX v0.89.6 - v1.02 / v1.05 -v1.24 -> Markus & Laszlo [overlay]]"
        ep_only = "true"
    strings:
        $a = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 ?? 8B 1E 83 ?? ?? 11 DB 72 ?? B8 01 00 00 00 01 DB 75}
    condition:
        $a
}