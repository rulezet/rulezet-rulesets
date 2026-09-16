rule TTP_XOR_QUAD_CurrentVersionRun_3e86 {
  strings:
    $key_3e86 = { 6d e9 [2] 49 e7 [2] 62 cb [2] 4c e9 [2] 58 f2 [2] 57 e8 [2] 49 f5 [2] 4b f4 [2] 50 f2 [2] 4c f5 [2] 50 da }

  condition:
    any of them
}