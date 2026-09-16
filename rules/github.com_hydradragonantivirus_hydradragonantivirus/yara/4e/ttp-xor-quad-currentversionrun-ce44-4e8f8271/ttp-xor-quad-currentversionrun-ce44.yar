rule TTP_XOR_QUAD_CurrentVersionRun_ce44 {
  strings:
    $key_ce44 = { 9d 2b [2] b9 25 [2] 92 09 [2] bc 2b [2] a8 30 [2] a7 2a [2] b9 37 [2] bb 36 [2] a0 30 [2] bc 37 [2] a0 18 }

  condition:
    any of them
}