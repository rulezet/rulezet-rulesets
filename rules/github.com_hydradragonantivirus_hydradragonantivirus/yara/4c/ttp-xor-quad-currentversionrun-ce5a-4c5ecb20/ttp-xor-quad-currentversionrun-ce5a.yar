rule TTP_XOR_QUAD_CurrentVersionRun_ce5a {
  strings:
    $key_ce5a = { 9d 35 [2] b9 3b [2] 92 17 [2] bc 35 [2] a8 2e [2] a7 34 [2] b9 29 [2] bb 28 [2] a0 2e [2] bc 29 [2] a0 06 }

  condition:
    any of them
}