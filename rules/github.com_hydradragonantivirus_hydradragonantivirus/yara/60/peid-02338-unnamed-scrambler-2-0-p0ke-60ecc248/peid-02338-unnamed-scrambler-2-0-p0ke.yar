rule PEiD_02338_Unnamed_Scrambler_2_0____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 2.0 -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC B9 0A 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 1C 2F 40 00 E8 C8 F1 FF FF 33 C0 55 68 FB 33 40 00 64 FF 30 64 89 20 BA 0C 34 40 00 B8 E4 54 40 00 E8 EF FE FF FF 8B D8 85 DB 75 07 6A 00 E8 5A F2 FF FF BA E8 54 40 00 8B C3 8B 0D E4 54 40 00 E8 74 }

  condition:
    $a
}