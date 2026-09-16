rule TTP_XOR_QUAD_CurrentVersionRun_ce59 {
  strings:
    $key_ce59 = { 9d 36 [2] b9 38 [2] 92 14 [2] bc 36 [2] a8 2d [2] a7 37 [2] b9 2a [2] bb 2b [2] a0 2d [2] bc 2a [2] a0 05 }

  condition:
    any of them
}