rule PEiD_02334_Unnamed_Scrambler_1_2C___1_2D____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 1.2C / 1.2D -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? 3A ?? ?? E8 ?? EC FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? D7 FF FF E8 ?? ?? FF FF B8 20 ?? ?? ?? 33 C9 BA 04 01 00 00 E8 ?? DB FF FF 68 04 01 00 00 68 20 ?? ?? ?? 6A 00 FF 15 10 }

  condition:
    $a
}