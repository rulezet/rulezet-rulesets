rule TTP_XOR_QUAD_CurrentVersionRun_5eaa {
  strings:
    $key_5eaa = { 0d c5 [2] 29 cb [2] 02 e7 [2] 2c c5 [2] 38 de [2] 37 c4 [2] 29 d9 [2] 2b d8 [2] 30 de [2] 2c d9 [2] 30 f6 }

  condition:
    any of them
}