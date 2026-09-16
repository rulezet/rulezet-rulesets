rule PEiD_01812_PseudoSigner_0_1__FSG_1_31_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [FSG 1.31] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }

  condition:
    $a
}