rule PEiD_01076_Microsoft_Visual_C___7_0_MFC_ {
  meta:
    description = "[Microsoft Visual C++ 7.0 MFC]"
    ep_only     = "true"

  strings:
    $a = { 6A 60 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 94 00 00 00 8B C7 E8 ?? ?? ?? ?? 89 }

  condition:
    $a
}