rule PEiD_01879_PseudoSigner_0_2__Microsoft_Visual_Basic_5_0___6_0__ {
  meta:
    description = "[PseudoSigner 0.2 [Microsoft Visual Basic 5.0 - 6.0]]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

  condition:
    $a
}