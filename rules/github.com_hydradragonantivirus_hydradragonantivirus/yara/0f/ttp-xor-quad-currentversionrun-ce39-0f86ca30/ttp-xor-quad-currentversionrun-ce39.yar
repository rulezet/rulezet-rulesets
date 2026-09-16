rule TTP_XOR_QUAD_CurrentVersionRun_ce39 {
  strings:
    $key_ce39 = { 9d 56 [2] b9 58 [2] 92 74 [2] bc 56 [2] a8 4d [2] a7 57 [2] b9 4a [2] bb 4b [2] a0 4d [2] bc 4a [2] a0 65 }

  condition:
    any of them
}