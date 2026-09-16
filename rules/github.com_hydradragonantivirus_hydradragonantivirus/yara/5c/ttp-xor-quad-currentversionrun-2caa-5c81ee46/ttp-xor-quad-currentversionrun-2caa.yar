rule TTP_XOR_QUAD_CurrentVersionRun_2caa {
  strings:
    $key_2caa = { 7f c5 [2] 5b cb [2] 70 e7 [2] 5e c5 [2] 4a de [2] 45 c4 [2] 5b d9 [2] 59 d8 [2] 42 de [2] 5e d9 [2] 42 f6 }

  condition:
    any of them
}