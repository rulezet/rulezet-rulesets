rule PEiD_01770_Private_Personal_Packer__PPP__1_0_2____ConquestOfTroy_com_ {
  meta:
    description = "[Private Personal Packer (PPP) 1.0.2 -> ConquestOfTroy.com]"
    ep_only     = "true"

  strings:
    $a = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 }

  condition:
    $a
}