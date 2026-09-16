rule BobPack1_00___BoB_Team_PEiD {
  meta:
    author      = "PEiD"
    description = "BobPack 1.00 --> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 ?? ?? ?? ?? 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 00 00 B8 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 44 24 1C 61 50 31 C0 C3 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 8B }

  condition:
    $a0
}