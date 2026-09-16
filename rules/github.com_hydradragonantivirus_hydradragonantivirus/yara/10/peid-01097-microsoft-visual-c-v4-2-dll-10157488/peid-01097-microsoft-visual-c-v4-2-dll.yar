rule PEiD_01097_Microsoft_Visual_C___v4_2_DLL_ {
  meta:
    description = "[Microsoft Visual C++ v4.2 DLL]"
    ep_only     = "true"

  strings:
    $a = { 53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75 }

  condition:
    $a
}