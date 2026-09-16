rule TTP_XOR_QUAD_CurrentVersionRun_d2aa {
  strings:
    $key_d2aa = { 81 c5 [2] a5 cb [2] 8e e7 [2] a0 c5 [2] b4 de [2] bb c4 [2] a5 d9 [2] a7 d8 [2] bc de [2] a0 d9 [2] bc f6 }

  condition:
    any of them
}