rule PEiD_01325_nSpack_V2_x____LiuXingPing_
{
    meta:
        description = "[nSpack V2.x -> LiuXingPing]"
        ep_only = "false"
    strings:
        $a = {9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5}
    condition:
        $a
}