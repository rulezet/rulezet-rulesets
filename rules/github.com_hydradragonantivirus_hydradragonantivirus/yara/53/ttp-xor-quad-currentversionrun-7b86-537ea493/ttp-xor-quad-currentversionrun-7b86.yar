rule TTP_XOR_QUAD_CurrentVersionRun_7b86 {
  strings:
    $key_7b86 = { 28 e9 [2] 0c e7 [2] 27 cb [2] 09 e9 [2] 1d f2 [2] 12 e8 [2] 0c f5 [2] 0e f4 [2] 15 f2 [2] 09 f5 [2] 15 da }

  condition:
    any of them
}