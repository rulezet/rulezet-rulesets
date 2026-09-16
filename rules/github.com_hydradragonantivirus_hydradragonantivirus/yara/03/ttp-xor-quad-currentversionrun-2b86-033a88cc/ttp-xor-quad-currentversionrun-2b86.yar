rule TTP_XOR_QUAD_CurrentVersionRun_2b86 {
  strings:
    $key_2b86 = { 78 e9 [2] 5c e7 [2] 77 cb [2] 59 e9 [2] 4d f2 [2] 42 e8 [2] 5c f5 [2] 5e f4 [2] 45 f2 [2] 59 f5 [2] 45 da }

  condition:
    any of them
}