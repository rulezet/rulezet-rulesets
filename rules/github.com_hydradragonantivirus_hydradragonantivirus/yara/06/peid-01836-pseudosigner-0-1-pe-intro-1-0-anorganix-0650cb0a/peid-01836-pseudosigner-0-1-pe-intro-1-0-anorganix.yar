rule PEiD_01836_PseudoSigner_0_1__PE_Intro_1_0_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [PE Intro 1.0] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9 }

  condition:
    $a
}