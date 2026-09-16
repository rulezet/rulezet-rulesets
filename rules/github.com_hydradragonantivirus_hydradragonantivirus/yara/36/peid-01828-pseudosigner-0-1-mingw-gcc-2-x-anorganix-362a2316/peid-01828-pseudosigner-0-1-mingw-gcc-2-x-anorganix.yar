rule PEiD_01828_PseudoSigner_0_1__MinGW_GCC_2_x_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [MinGW GCC 2.x] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

  condition:
    $a
}