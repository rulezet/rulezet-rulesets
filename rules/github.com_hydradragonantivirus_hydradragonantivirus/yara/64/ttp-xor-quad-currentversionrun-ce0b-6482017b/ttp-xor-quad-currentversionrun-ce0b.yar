rule TTP_XOR_QUAD_CurrentVersionRun_ce0b {
  strings:
    $key_ce0b = { 9d 64 [2] b9 6a [2] 92 46 [2] bc 64 [2] a8 7f [2] a7 65 [2] b9 78 [2] bb 79 [2] a0 7f [2] bc 78 [2] a0 57 }

  condition:
    any of them
}