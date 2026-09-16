rule TTP_XOR_QUAD_CurrentVersionRun_4caa {
  strings:
    $key_4caa = { 1f c5 [2] 3b cb [2] 10 e7 [2] 3e c5 [2] 2a de [2] 25 c4 [2] 3b d9 [2] 39 d8 [2] 22 de [2] 3e d9 [2] 22 f6 }

  condition:
    any of them
}