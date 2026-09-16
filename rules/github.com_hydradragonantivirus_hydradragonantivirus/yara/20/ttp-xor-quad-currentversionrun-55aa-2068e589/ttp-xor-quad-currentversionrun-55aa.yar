rule TTP_XOR_QUAD_CurrentVersionRun_55aa {
  strings:
    $key_55aa = { 06 c5 [2] 22 cb [2] 09 e7 [2] 27 c5 [2] 33 de [2] 3c c4 [2] 22 d9 [2] 20 d8 [2] 3b de [2] 27 d9 [2] 3b f6 }

  condition:
    any of them
}