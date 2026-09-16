rule PEiD_00157_Armadillo_v2_10b2_ {
  meta:
    description = "[Armadillo v2.10b2]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}