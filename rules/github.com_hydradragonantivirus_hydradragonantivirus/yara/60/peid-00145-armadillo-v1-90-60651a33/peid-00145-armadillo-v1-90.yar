rule PEiD_00145_Armadillo_v1_90_ {
  meta:
    description = "[Armadillo v1.90]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}