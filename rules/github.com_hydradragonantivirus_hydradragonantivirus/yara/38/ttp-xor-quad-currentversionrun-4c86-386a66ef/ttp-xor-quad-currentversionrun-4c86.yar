rule TTP_XOR_QUAD_CurrentVersionRun_4c86 {
  strings:
    $key_4c86 = { 1f e9 [2] 3b e7 [2] 10 cb [2] 3e e9 [2] 2a f2 [2] 25 e8 [2] 3b f5 [2] 39 f4 [2] 22 f2 [2] 3e f5 [2] 22 da }

  condition:
    any of them
}