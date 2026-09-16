rule TTP_XOR_QUAD_CurrentVersionRun_ce6b {
  strings:
    $key_ce6b = { 9d 04 [2] b9 0a [2] 92 26 [2] bc 04 [2] a8 1f [2] a7 05 [2] b9 18 [2] bb 19 [2] a0 1f [2] bc 18 [2] a0 37 }

  condition:
    any of them
}