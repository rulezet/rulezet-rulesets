rule TTP_XOR_QUAD_CurrentVersionRun_25aa {
  strings:
    $key_25aa = { 76 c5 [2] 52 cb [2] 79 e7 [2] 57 c5 [2] 43 de [2] 4c c4 [2] 52 d9 [2] 50 d8 [2] 4b de [2] 57 d9 [2] 4b f6 }

  condition:
    any of them
}