rule PEiD_02089_SimplePack_1_11_Method_1____bagie_TMX__ {
  meta:
    description = "[SimplePack 1.11 Method 1 -> bagie[TMX]]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC }

  condition:
    $a
}