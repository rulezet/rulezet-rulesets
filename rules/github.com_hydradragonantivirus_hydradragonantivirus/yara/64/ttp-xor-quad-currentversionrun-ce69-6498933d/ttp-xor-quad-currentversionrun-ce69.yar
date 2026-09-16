rule TTP_XOR_QUAD_CurrentVersionRun_ce69 {
  strings:
    $key_ce69 = { 9d 06 [2] b9 08 [2] 92 24 [2] bc 06 [2] a8 1d [2] a7 07 [2] b9 1a [2] bb 1b [2] a0 1d [2] bc 1a [2] a0 35 }

  condition:
    any of them
}