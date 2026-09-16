rule PEiD_01092_Microsoft_Visual_C_______ {
  meta:
    description = "[Microsoft Visual C++ ?.?]"
    ep_only     = "true"

  strings:
    $a = { 83 ?? ?? 6A 00 FF 15 F8 10 0B B0 8D ?? ?? ?? 51 6A 08 6A 00 6A 00 68 }

  condition:
    $a
}