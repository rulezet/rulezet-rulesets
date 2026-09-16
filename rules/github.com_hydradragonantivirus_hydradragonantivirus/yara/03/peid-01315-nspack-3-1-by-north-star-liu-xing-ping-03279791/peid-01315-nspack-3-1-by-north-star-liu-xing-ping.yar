rule PEiD_01315_NsPack_3_1_by_North_Star__Liu_Xing_Ping__ {
  meta:
    description = "[NsPack 3.1 by North Star (Liu Xing Ping)]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 }

  condition:
    $a
}