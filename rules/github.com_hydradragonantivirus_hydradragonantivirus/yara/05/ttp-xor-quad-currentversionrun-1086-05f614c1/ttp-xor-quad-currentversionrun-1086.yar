rule TTP_XOR_QUAD_CurrentVersionRun_1086 {
  strings:
    $key_1086 = { 43 e9 [2] 67 e7 [2] 4c cb [2] 62 e9 [2] 76 f2 [2] 79 e8 [2] 67 f5 [2] 65 f4 [2] 7e f2 [2] 62 f5 [2] 7e da }

  condition:
    any of them
}