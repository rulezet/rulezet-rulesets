rule PEiD_00148_Armadillo_v1_90b2_ {
  meta:
    description = "[Armadillo v1.90b2]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}