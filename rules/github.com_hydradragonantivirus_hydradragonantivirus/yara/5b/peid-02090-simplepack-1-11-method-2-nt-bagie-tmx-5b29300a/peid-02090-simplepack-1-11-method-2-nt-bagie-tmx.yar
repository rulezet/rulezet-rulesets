rule PEiD_02090_SimplePack_1_11_Method_2_NT_____bagie_TMX__ {
  meta:
    description = "[SimplePack 1.11 Method 2(NT) -> bagie[TMX]]"
    ep_only     = "true"

  strings:
    $a = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 }

  condition:
    $a
}