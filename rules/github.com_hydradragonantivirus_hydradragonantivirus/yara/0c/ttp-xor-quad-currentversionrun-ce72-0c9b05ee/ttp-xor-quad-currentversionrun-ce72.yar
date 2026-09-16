rule TTP_XOR_QUAD_CurrentVersionRun_ce72 {
  strings:
    $key_ce72 = { 9d 1d [2] b9 13 [2] 92 3f [2] bc 1d [2] a8 06 [2] a7 1c [2] b9 01 [2] bb 00 [2] a0 06 [2] bc 01 [2] a0 2e }

  condition:
    any of them
}