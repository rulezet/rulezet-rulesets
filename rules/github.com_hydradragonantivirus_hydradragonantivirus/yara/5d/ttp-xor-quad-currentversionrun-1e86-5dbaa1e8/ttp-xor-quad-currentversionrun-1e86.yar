rule TTP_XOR_QUAD_CurrentVersionRun_1e86 {
  strings:
    $key_1e86 = { 4d e9 [2] 69 e7 [2] 42 cb [2] 6c e9 [2] 78 f2 [2] 77 e8 [2] 69 f5 [2] 6b f4 [2] 70 f2 [2] 6c f5 [2] 70 da }

  condition:
    any of them
}