rule TTP_XOR_QUAD_CurrentVersionRun_1caa {
  strings:
    $key_1caa = { 4f c5 [2] 6b cb [2] 40 e7 [2] 6e c5 [2] 7a de [2] 75 c4 [2] 6b d9 [2] 69 d8 [2] 72 de [2] 6e d9 [2] 72 f6 }

  condition:
    any of them
}