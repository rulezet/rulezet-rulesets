rule TTP_XOR_QUAD_CurrentVersionRun_17aa {
  strings:
    $key_17aa = { 44 c5 [2] 60 cb [2] 4b e7 [2] 65 c5 [2] 71 de [2] 7e c4 [2] 60 d9 [2] 62 d8 [2] 79 de [2] 65 d9 [2] 79 f6 }

  condition:
    any of them
}