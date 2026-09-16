rule TTP_XOR_QUAD_CurrentVersionRun_7baa {
  strings:
    $key_7baa = { 28 c5 [2] 0c cb [2] 27 e7 [2] 09 c5 [2] 1d de [2] 12 c4 [2] 0c d9 [2] 0e d8 [2] 15 de [2] 09 d9 [2] 15 f6 }

  condition:
    any of them
}