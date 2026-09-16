rule PEiD_00110_ARJ_SFX_Custom_ {
  meta:
    description = "[ARJ SFX Custom]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 18 C0 40 00 68 C4 A1 40 00 50 64 89 25 00 00 00 00 83 EC 60 53 56 57 89 65 E8 FF 15 38 03 41 00 A3 D0 D6 40 00 33 C0 A0 D1 D6 40 00 A3 DC D6 40 00 A1 D0 D6 }

  condition:
    $a
}