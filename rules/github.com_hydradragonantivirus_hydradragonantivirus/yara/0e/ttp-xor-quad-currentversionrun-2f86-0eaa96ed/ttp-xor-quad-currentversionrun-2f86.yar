rule TTP_XOR_QUAD_CurrentVersionRun_2f86 {
  strings:
    $key_2f86 = { 7c e9 [2] 58 e7 [2] 73 cb [2] 5d e9 [2] 49 f2 [2] 46 e8 [2] 58 f5 [2] 5a f4 [2] 41 f2 [2] 5d f5 [2] 41 da }

  condition:
    any of them
}