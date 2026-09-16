rule TTP_XOR_QUAD_CurrentVersionRun_7caa {
  strings:
    $key_7caa = { 2f c5 [2] 0b cb [2] 20 e7 [2] 0e c5 [2] 1a de [2] 15 c4 [2] 0b d9 [2] 09 d8 [2] 12 de [2] 0e d9 [2] 12 f6 }

  condition:
    any of them
}