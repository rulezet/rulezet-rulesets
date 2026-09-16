rule PEiD_01881_PseudoSigner_0_2__MinGW_GCC_2_x__ {
  meta:
    description = "[PseudoSigner 0.2 [MinGW GCC 2.x]]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

  condition:
    $a
}