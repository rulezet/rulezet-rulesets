rule PEiD_01120_Microsoft_Visual_C___v7_1_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v7.1 DLL]"
    ep_only     = "true"

  strings:
    $a = { 83 7C 24 08 01 75 ?? ?? ?? 24 04 50 A3 ?? ?? ?? 50 FF 15 00 10 ?? 50 33 C0 40 C2 0C 00 }

  condition:
    $a
}