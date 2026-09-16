rule TTP_XOR_QUAD_CurrentVersionRun_d55c {
  strings:
    $key_d55c = { 86 33 [2] a2 3d [2] 89 11 [2] a7 33 [2] b3 28 [2] bc 32 [2] a2 2f [2] a0 2e [2] bb 28 [2] a7 2f [2] bb 00 }

  condition:
    any of them
}