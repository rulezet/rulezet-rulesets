rule TTP_XOR_QUAD_CurrentVersionRun_54aa {
  strings:
    $key_54aa = { 07 c5 [2] 23 cb [2] 08 e7 [2] 26 c5 [2] 32 de [2] 3d c4 [2] 23 d9 [2] 21 d8 [2] 3a de [2] 26 d9 [2] 3a f6 }

  condition:
    any of them
}