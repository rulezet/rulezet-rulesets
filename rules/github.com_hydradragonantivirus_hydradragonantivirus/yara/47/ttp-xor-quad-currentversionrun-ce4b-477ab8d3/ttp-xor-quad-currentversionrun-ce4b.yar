rule TTP_XOR_QUAD_CurrentVersionRun_ce4b {
  strings:
    $key_ce4b = { 9d 24 [2] b9 2a [2] 92 06 [2] bc 24 [2] a8 3f [2] a7 25 [2] b9 38 [2] bb 39 [2] a0 3f [2] bc 38 [2] a0 17 }

  condition:
    any of them
}