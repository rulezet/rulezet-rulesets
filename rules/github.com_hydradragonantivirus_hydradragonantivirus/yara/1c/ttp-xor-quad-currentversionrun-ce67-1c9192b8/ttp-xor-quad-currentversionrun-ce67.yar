rule TTP_XOR_QUAD_CurrentVersionRun_ce67 {
  strings:
    $key_ce67 = { 9d 08 [2] b9 06 [2] 92 2a [2] bc 08 [2] a8 13 [2] a7 09 [2] b9 14 [2] bb 15 [2] a0 13 [2] bc 14 [2] a0 3b }

  condition:
    any of them
}