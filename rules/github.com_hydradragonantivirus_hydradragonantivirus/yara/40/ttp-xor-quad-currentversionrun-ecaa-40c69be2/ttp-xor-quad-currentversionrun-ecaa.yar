rule TTP_XOR_QUAD_CurrentVersionRun_ecaa {
  strings:
    $key_ecaa = { bf c5 [2] 9b cb [2] b0 e7 [2] 9e c5 [2] 8a de [2] 85 c4 [2] 9b d9 [2] 99 d8 [2] 82 de [2] 9e d9 [2] 82 f6 }

  condition:
    any of them
}