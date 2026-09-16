rule TTP_XOR_QUAD_CurrentVersionRun_ce16 {
  strings:
    $key_ce16 = { 9d 79 [2] b9 77 [2] 92 5b [2] bc 79 [2] a8 62 [2] a7 78 [2] b9 65 [2] bb 64 [2] a0 62 [2] bc 65 [2] a0 4a }

  condition:
    any of them
}