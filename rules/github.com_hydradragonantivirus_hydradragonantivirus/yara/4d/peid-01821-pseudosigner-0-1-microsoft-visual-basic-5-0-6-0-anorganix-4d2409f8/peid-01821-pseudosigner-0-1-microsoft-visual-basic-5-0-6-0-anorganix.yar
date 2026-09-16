rule PEiD_01821_PseudoSigner_0_1__Microsoft_Visual_Basic_5_0___6_0_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Microsoft Visual Basic 5.0 - 6.0] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

  condition:
    $a
}