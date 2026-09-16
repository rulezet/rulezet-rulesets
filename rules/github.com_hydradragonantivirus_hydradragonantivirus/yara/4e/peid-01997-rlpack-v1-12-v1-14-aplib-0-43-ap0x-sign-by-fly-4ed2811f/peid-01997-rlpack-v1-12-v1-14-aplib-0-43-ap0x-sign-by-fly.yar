rule PEiD_01997_RLPack_V1_12_V1_14__aPlib_0_43_____ap0x___Sign_by_fly_ {
  meta:
    description = "[RLPack V1.12-V1.14 (aPlib 0.43) -> ap0x ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }

  condition:
    $a
}