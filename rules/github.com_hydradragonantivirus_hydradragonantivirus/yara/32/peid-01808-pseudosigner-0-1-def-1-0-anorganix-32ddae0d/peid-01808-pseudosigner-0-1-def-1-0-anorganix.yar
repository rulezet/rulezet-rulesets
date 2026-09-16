rule PEiD_01808_PseudoSigner_0_1__DEF_1_0_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [DEF 1.0] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9 }

  condition:
    $a
}