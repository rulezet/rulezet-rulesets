rule TTP_XOR_QUAD_CurrentVersionRun_6b86 {
  strings:
    $key_6b86 = { 38 e9 [2] 1c e7 [2] 37 cb [2] 19 e9 [2] 0d f2 [2] 02 e8 [2] 1c f5 [2] 1e f4 [2] 05 f2 [2] 19 f5 [2] 05 da }

  condition:
    any of them
}