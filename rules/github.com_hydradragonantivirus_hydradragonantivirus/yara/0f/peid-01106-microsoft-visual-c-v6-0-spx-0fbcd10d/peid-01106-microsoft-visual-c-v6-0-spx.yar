rule PEiD_01106_Microsoft_Visual_C___v6_0_SPx_ {
  meta:
    description = "[Microsoft Visual C++ v6.0 SPx]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }

  condition:
    $a
}