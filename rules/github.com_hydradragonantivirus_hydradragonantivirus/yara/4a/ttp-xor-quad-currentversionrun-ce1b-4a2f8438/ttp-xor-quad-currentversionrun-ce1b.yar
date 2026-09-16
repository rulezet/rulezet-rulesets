rule TTP_XOR_QUAD_CurrentVersionRun_ce1b {
  strings:
    $key_ce1b = { 9d 74 [2] b9 7a [2] 92 56 [2] bc 74 [2] a8 6f [2] a7 75 [2] b9 68 [2] bb 69 [2] a0 6f [2] bc 68 [2] a0 47 }

  condition:
    any of them
}