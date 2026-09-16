rule TTP_XOR_QUAD_CurrentVersionRun_ce1a {
  strings:
    $key_ce1a = { 9d 75 [2] b9 7b [2] 92 57 [2] bc 75 [2] a8 6e [2] a7 74 [2] b9 69 [2] bb 68 [2] a0 6e [2] bc 69 [2] a0 46 }

  condition:
    any of them
}