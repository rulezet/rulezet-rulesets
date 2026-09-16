rule PEiD_01100_Microsoft_Visual_C___v4_x_ {
  meta:
    description = "[Microsoft Visual C++ v4.x]"
    ep_only     = "true"

  strings:
    $a = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 }

  condition:
    $a
}