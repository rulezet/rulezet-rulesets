rule TTP_XOR_QUAD_CurrentVersionRun_ce76 {
  strings:
    $key_ce76 = { 9d 19 [2] b9 17 [2] 92 3b [2] bc 19 [2] a8 02 [2] a7 18 [2] b9 05 [2] bb 04 [2] a0 02 [2] bc 05 [2] a0 2a }

  condition:
    any of them
}