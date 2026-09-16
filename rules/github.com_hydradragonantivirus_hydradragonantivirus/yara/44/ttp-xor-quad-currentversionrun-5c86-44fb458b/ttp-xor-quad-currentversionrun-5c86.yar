rule TTP_XOR_QUAD_CurrentVersionRun_5c86 {
  strings:
    $key_5c86 = { 0f e9 [2] 2b e7 [2] 00 cb [2] 2e e9 [2] 3a f2 [2] 35 e8 [2] 2b f5 [2] 29 f4 [2] 32 f2 [2] 2e f5 [2] 32 da }

  condition:
    any of them
}