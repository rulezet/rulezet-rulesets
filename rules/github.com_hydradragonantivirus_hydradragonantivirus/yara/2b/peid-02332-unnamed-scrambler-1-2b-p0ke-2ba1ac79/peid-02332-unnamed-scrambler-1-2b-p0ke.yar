rule PEiD_02332_Unnamed_Scrambler_1_2B____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 1.2B -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 D8 53 56 57 33 C0 89 45 D8 89 45 DC 89 45 E0 89 45 E4 89 45 E8 B8 70 3A 40 00 E8 C4 EC FF FF 33 C0 55 68 5C 3F 40 00 64 FF 30 64 89 20 E8 C5 D7 FF FF E8 5C F5 FF FF B8 20 65 40 00 33 C9 BA 04 01 00 00 E8 D3 DB FF FF 68 04 01 00 00 68 20 65 }

  condition:
    $a
}