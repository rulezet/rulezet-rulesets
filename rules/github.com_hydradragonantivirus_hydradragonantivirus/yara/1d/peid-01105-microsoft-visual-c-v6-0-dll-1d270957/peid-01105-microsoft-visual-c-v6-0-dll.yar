rule PEiD_01105_Microsoft_Visual_C___v6_0_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v6.0 DLL]"
    ep_only     = "true"

  strings:
    $a = { 83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? ?? 00 10 E8 8B FF FF FF }

  condition:
    $a
}