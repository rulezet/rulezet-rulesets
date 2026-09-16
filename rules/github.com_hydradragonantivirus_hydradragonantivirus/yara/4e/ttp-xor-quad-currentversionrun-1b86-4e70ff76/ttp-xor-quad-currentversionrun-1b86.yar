rule TTP_XOR_QUAD_CurrentVersionRun_1b86 {
  strings:
    $key_1b86 = { 48 e9 [2] 6c e7 [2] 47 cb [2] 69 e9 [2] 7d f2 [2] 72 e8 [2] 6c f5 [2] 6e f4 [2] 75 f2 [2] 69 f5 [2] 75 da }

  condition:
    any of them
}