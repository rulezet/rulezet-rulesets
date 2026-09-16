rule PEiD_00137_Armadillo_v1_60a_ {
  meta:
    description = "[Armadillo v1.60a]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}