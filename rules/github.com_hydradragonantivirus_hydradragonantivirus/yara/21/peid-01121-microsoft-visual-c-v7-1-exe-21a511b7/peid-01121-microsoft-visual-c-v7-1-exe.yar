rule PEiD_01121_Microsoft_Visual_C___v7_1_EXE_ {
  meta:
    description = "[Microsoft Visual C++ v7.1 EXE]"
    ep_only     = "true"

  strings:
    $a = { 6A ?? 68 ?? ?? ?? 01 E8 ?? ?? 00 00 66 81 3D 00 00 00 01 4D 5A 75 ?? A1 3C 00 00 01 ?? ?? 00 00 00 01 }

  condition:
    $a
}