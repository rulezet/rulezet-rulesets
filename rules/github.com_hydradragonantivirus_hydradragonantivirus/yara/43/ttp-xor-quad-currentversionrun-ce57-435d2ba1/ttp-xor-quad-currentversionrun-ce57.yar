rule TTP_XOR_QUAD_CurrentVersionRun_ce57 {
  strings:
    $key_ce57 = { 9d 38 [2] b9 36 [2] 92 1a [2] bc 38 [2] a8 23 [2] a7 39 [2] b9 24 [2] bb 25 [2] a0 23 [2] bc 24 [2] a0 0b }

  condition:
    any of them
}