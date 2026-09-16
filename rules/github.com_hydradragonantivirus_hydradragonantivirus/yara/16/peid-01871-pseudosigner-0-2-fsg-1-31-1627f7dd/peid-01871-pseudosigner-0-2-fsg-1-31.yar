rule PEiD_01871_PseudoSigner_0_2__FSG_1_31__ {
  meta:
    description = "[PseudoSigner 0.2 [FSG 1.31]]"
    ep_only     = "true"

  strings:
    $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }

  condition:
    $a
}