rule PEiD_00159_Armadillo_v2_20b1_ {
  meta:
    description = "[Armadillo v2.20b1]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}