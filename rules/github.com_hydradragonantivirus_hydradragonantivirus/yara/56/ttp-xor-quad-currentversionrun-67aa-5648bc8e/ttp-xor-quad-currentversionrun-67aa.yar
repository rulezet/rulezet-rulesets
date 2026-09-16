rule TTP_XOR_QUAD_CurrentVersionRun_67aa {
  strings:
    $key_67aa = { 34 c5 [2] 10 cb [2] 3b e7 [2] 15 c5 [2] 01 de [2] 0e c4 [2] 10 d9 [2] 12 d8 [2] 09 de [2] 15 d9 [2] 09 f6 }

  condition:
    any of them
}