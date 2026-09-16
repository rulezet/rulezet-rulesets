rule PEiD_01981_RLPack_1_18__aPlib_0_43_____ap0x_ {
  meta:
    description = "[RLPack 1.18 (aPlib 0.43) -> ap0x]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

  condition:
    $a
}