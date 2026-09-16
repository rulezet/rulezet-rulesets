rule TTP_XOR_QUAD_CurrentVersionRun_2086 {
  strings:
    $key_2086 = { 73 e9 [2] 57 e7 [2] 7c cb [2] 52 e9 [2] 46 f2 [2] 49 e8 [2] 57 f5 [2] 55 f4 [2] 4e f2 [2] 52 f5 [2] 4e da }

  condition:
    any of them
}