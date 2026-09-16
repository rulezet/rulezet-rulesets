rule TTP_XOR_QUAD_CurrentVersionRun_ce58 {
  strings:
    $key_ce58 = { 9d 37 [2] b9 39 [2] 92 15 [2] bc 37 [2] a8 2c [2] a7 36 [2] b9 2b [2] bb 2a [2] a0 2c [2] bc 2b [2] a0 04 }

  condition:
    any of them
}