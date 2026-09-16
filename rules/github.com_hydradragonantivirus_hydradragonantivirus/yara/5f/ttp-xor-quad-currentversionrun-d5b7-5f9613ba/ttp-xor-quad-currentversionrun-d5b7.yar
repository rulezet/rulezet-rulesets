rule TTP_XOR_QUAD_CurrentVersionRun_d5b7 {
  strings:
    $key_d5b7 = { 86 d8 [2] a2 d6 [2] 89 fa [2] a7 d8 [2] b3 c3 [2] bc d9 [2] a2 c4 [2] a0 c5 [2] bb c3 [2] a7 c4 [2] bb eb }

  condition:
    any of them
}