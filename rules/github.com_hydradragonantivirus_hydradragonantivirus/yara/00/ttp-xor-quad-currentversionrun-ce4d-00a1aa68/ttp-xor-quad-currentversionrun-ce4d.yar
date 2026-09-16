rule TTP_XOR_QUAD_CurrentVersionRun_ce4d {
  strings:
    $key_ce4d = { 9d 22 [2] b9 2c [2] 92 00 [2] bc 22 [2] a8 39 [2] a7 23 [2] b9 3e [2] bb 3f [2] a0 39 [2] bc 3e [2] a0 11 }

  condition:
    any of them
}