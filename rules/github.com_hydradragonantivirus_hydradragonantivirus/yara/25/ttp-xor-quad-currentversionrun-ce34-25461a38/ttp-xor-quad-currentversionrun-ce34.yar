rule TTP_XOR_QUAD_CurrentVersionRun_ce34 {
  strings:
    $key_ce34 = { 9d 5b [2] b9 55 [2] 92 79 [2] bc 5b [2] a8 40 [2] a7 5a [2] b9 47 [2] bb 46 [2] a0 40 [2] bc 47 [2] a0 68 }

  condition:
    any of them
}