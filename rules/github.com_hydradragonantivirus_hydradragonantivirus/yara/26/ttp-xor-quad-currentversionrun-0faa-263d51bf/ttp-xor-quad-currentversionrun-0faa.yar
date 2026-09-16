rule TTP_XOR_QUAD_CurrentVersionRun_0faa {
  strings:
    $key_0faa = { 5c c5 [2] 78 cb [2] 53 e7 [2] 7d c5 [2] 69 de [2] 66 c4 [2] 78 d9 [2] 7a d8 [2] 61 de [2] 7d d9 [2] 61 f6 }

  condition:
    any of them
}