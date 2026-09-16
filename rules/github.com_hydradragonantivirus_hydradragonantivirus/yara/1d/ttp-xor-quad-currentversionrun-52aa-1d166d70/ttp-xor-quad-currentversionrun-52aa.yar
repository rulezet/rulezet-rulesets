rule TTP_XOR_QUAD_CurrentVersionRun_52aa {
  strings:
    $key_52aa = { 01 c5 [2] 25 cb [2] 0e e7 [2] 20 c5 [2] 34 de [2] 3b c4 [2] 25 d9 [2] 27 d8 [2] 3c de [2] 20 d9 [2] 3c f6 }

  condition:
    any of them
}