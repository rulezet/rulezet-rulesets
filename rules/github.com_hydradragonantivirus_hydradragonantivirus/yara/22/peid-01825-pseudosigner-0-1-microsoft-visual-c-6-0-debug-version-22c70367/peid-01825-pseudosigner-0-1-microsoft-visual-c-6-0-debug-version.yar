rule PEiD_01825_PseudoSigner_0_1__Microsoft_Visual_C___6_0__Debug_Version___ {
  meta:
    description = "[PseudoSigner 0.1 [Microsoft Visual C++ 6.0 (Debug Version)]]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }

  condition:
    $a
}