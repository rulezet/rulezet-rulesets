rule PEiD_01823_PseudoSigner_0_1__Microsoft_Visual_C___5_0___MFC______Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Microsoft Visual C++ 5.0+ (MFC)] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9 }

  condition:
    $a
}