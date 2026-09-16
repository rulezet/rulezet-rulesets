rule TTP_XOR_QUAD_CurrentVersionRun_2baa {
  strings:
    $key_2baa = { 78 c5 [2] 5c cb [2] 77 e7 [2] 59 c5 [2] 4d de [2] 42 c4 [2] 5c d9 [2] 5e d8 [2] 45 de [2] 59 d9 [2] 45 f6 }

  condition:
    any of them
}