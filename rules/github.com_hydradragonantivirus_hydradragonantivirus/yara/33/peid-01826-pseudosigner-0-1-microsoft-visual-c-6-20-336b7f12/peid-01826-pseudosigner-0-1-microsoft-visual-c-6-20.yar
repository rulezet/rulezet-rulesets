rule PEiD_01826_PseudoSigner_0_1__Microsoft_Visual_C___6_20__ {
  meta:
    description = "[PseudoSigner 0.1 [Microsoft Visual C++ 6.20]]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B }

  condition:
    $a
}