rule PEiD_01094_Microsoft_Visual_C___DLL_ {
  meta:
    description = "[Microsoft Visual C++ DLL]"
    ep_only     = "true"

  strings:
    $a = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14 }

  condition:
    $a
}