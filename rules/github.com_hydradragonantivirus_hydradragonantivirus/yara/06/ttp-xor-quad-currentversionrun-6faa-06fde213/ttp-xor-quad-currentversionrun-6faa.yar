rule TTP_XOR_QUAD_CurrentVersionRun_6faa {
  strings:
    $key_6faa = { 3c c5 [2] 18 cb [2] 33 e7 [2] 1d c5 [2] 09 de [2] 06 c4 [2] 18 d9 [2] 1a d8 [2] 01 de [2] 1d d9 [2] 01 f6 }

  condition:
    any of them
}