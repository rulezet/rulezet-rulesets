rule TTP_XOR_QUAD_CurrentVersionRun_ce5c {
  strings:
    $key_ce5c = { 9d 33 [2] b9 3d [2] 92 11 [2] bc 33 [2] a8 28 [2] a7 32 [2] b9 2f [2] bb 2e [2] a0 28 [2] bc 2f [2] a0 00 }

  condition:
    any of them
}