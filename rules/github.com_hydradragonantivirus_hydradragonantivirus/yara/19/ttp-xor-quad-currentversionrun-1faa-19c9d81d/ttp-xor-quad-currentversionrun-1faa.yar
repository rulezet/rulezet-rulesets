rule TTP_XOR_QUAD_CurrentVersionRun_1faa {
  strings:
    $key_1faa = { 4c c5 [2] 68 cb [2] 43 e7 [2] 6d c5 [2] 79 de [2] 76 c4 [2] 68 d9 [2] 6a d8 [2] 71 de [2] 6d d9 [2] 71 f6 }

  condition:
    any of them
}