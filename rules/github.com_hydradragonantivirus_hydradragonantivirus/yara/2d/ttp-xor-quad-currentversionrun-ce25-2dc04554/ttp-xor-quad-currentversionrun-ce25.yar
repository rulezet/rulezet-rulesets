rule TTP_XOR_QUAD_CurrentVersionRun_ce25 {
  strings:
    $key_ce25 = { 9d 4a [2] b9 44 [2] 92 68 [2] bc 4a [2] a8 51 [2] a7 4b [2] b9 56 [2] bb 57 [2] a0 51 [2] bc 56 [2] a0 79 }

  condition:
    any of them
}