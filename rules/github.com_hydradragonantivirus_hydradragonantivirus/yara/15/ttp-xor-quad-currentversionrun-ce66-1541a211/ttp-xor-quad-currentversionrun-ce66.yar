rule TTP_XOR_QUAD_CurrentVersionRun_ce66 {
  strings:
    $key_ce66 = { 9d 09 [2] b9 07 [2] 92 2b [2] bc 09 [2] a8 12 [2] a7 08 [2] b9 15 [2] bb 14 [2] a0 12 [2] bc 15 [2] a0 3a }

  condition:
    any of them
}