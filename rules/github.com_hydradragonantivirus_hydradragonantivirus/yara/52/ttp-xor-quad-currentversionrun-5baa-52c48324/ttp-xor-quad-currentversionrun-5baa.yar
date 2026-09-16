rule TTP_XOR_QUAD_CurrentVersionRun_5baa {
  strings:
    $key_5baa = { 08 c5 [2] 2c cb [2] 07 e7 [2] 29 c5 [2] 3d de [2] 32 c4 [2] 2c d9 [2] 2e d8 [2] 35 de [2] 29 d9 [2] 35 f6 }

  condition:
    any of them
}