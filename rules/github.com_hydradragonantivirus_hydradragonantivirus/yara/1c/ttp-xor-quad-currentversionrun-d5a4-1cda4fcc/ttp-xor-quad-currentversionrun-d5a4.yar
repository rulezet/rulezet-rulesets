rule TTP_XOR_QUAD_CurrentVersionRun_d5a4 {
  strings:
    $key_d5a4 = { 86 cb [2] a2 c5 [2] 89 e9 [2] a7 cb [2] b3 d0 [2] bc ca [2] a2 d7 [2] a0 d6 [2] bb d0 [2] a7 d7 [2] bb f8 }

  condition:
    any of them
}