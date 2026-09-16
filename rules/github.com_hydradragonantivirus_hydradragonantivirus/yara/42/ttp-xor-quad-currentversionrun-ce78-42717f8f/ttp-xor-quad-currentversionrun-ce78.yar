rule TTP_XOR_QUAD_CurrentVersionRun_ce78 {
  strings:
    $key_ce78 = { 9d 17 [2] b9 19 [2] 92 35 [2] bc 17 [2] a8 0c [2] a7 16 [2] b9 0b [2] bb 0a [2] a0 0c [2] bc 0b [2] a0 24 }

  condition:
    any of them
}