rule TTP_XOR_QUAD_CurrentVersionRun_75aa {
  strings:
    $key_75aa = { 26 c5 [2] 02 cb [2] 29 e7 [2] 07 c5 [2] 13 de [2] 1c c4 [2] 02 d9 [2] 00 d8 [2] 1b de [2] 07 d9 [2] 1b f6 }

  condition:
    any of them
}