rule PEiD_01318_NsPack_3_x____Liu_Xing_Ping_
{
    meta:
        description = "[NsPack 3.x -> Liu Xing Ping]"
        ep_only = "true"
    strings:
        $a = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D}
    condition:
        $a
}