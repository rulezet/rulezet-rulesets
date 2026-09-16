rule TTP_XOR_QUAD_CurrentVersionRun_ce17 {
  strings:
    $key_ce17 = { 9d 78 [2] b9 76 [2] 92 5a [2] bc 78 [2] a8 63 [2] a7 79 [2] b9 64 [2] bb 65 [2] a0 63 [2] bc 64 [2] a0 4b }

  condition:
    any of them
}