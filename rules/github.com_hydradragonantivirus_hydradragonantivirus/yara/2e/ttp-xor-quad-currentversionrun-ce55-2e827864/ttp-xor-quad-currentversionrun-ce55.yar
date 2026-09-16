rule TTP_XOR_QUAD_CurrentVersionRun_ce55 {
  strings:
    $key_ce55 = { 9d 3a [2] b9 34 [2] 92 18 [2] bc 3a [2] a8 21 [2] a7 3b [2] b9 26 [2] bb 27 [2] a0 21 [2] bc 26 [2] a0 09 }

  condition:
    any of them
}