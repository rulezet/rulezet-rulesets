rule TTP_XOR_QUAD_CurrentVersionRun_fcaa {
  strings:
    $key_fcaa = { af c5 [2] 8b cb [2] a0 e7 [2] 8e c5 [2] 9a de [2] 95 c4 [2] 8b d9 [2] 89 d8 [2] 92 de [2] 8e d9 [2] 92 f6 }

  condition:
    any of them
}