rule TTP_XOR_QUAD_CurrentVersionRun_6baa {
  strings:
    $key_6baa = { 38 c5 [2] 1c cb [2] 37 e7 [2] 19 c5 [2] 0d de [2] 02 c4 [2] 1c d9 [2] 1e d8 [2] 05 de [2] 19 d9 [2] 05 f6 }

  condition:
    any of them
}