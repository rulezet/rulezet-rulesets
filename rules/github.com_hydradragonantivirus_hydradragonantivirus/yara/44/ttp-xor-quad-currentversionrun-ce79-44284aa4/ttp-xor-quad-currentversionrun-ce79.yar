rule TTP_XOR_QUAD_CurrentVersionRun_ce79 {
  strings:
    $key_ce79 = { 9d 16 [2] b9 18 [2] 92 34 [2] bc 16 [2] a8 0d [2] a7 17 [2] b9 0a [2] bb 0b [2] a0 0d [2] bc 0a [2] a0 25 }

  condition:
    any of them
}