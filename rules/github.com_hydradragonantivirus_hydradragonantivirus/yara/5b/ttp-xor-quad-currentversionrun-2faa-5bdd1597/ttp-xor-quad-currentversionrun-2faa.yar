rule TTP_XOR_QUAD_CurrentVersionRun_2faa {
  strings:
    $key_2faa = { 7c c5 [2] 58 cb [2] 73 e7 [2] 5d c5 [2] 49 de [2] 46 c4 [2] 58 d9 [2] 5a d8 [2] 41 de [2] 5d d9 [2] 41 f6 }

  condition:
    any of them
}