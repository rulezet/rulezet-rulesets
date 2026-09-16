rule PEiD_01842_PseudoSigner_0_1__PESHiELD_0_25_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [PESHiELD 0.25] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9 }

  condition:
    $a
}