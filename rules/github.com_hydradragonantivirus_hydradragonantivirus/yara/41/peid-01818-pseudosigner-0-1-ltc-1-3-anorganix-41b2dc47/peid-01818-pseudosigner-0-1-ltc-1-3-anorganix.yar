rule PEiD_01818_PseudoSigner_0_1__LTC_1_3_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [LTC 1.3] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9 }

  condition:
    $a
}