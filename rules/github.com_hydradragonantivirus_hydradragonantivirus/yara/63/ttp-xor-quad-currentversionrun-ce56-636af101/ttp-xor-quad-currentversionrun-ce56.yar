rule TTP_XOR_QUAD_CurrentVersionRun_ce56 {
  strings:
    $key_ce56 = { 9d 39 [2] b9 37 [2] 92 1b [2] bc 39 [2] a8 22 [2] a7 38 [2] b9 25 [2] bb 24 [2] a0 22 [2] bc 25 [2] a0 0a }

  condition:
    any of them
}