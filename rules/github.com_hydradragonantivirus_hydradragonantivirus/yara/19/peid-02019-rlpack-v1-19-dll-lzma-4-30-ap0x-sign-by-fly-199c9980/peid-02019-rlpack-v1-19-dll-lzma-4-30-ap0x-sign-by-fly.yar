rule PEiD_02019_RLPack_V1_19_Dll__LZMA_4_30_____ap0x___Sign_by_fly_ {
  meta:
    description = "[RLPack V1.19 Dll (LZMA 4.30) -> ap0x ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA }

  condition:
    $a
}