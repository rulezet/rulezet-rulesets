rule TTP_XOR_QUAD_CurrentVersionRun_60aa {
  strings:
    $key_60aa = { 33 c5 [2] 17 cb [2] 3c e7 [2] 12 c5 [2] 06 de [2] 09 c4 [2] 17 d9 [2] 15 d8 [2] 0e de [2] 12 d9 [2] 0e f6 }

  condition:
    any of them
}