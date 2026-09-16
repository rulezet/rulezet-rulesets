rule TTP_XOR_QUAD_CurrentVersionRun_0b86 {
  strings:
    $key_0b86 = { 58 e9 [2] 7c e7 [2] 57 cb [2] 79 e9 [2] 6d f2 [2] 62 e8 [2] 7c f5 [2] 7e f4 [2] 65 f2 [2] 79 f5 [2] 65 da }

  condition:
    any of them
}