rule TTP_XOR_QUAD_CurrentVersionRun_4d86 {
  strings:
    $key_4d86 = { 1e e9 [2] 3a e7 [2] 11 cb [2] 3f e9 [2] 2b f2 [2] 24 e8 [2] 3a f5 [2] 38 f4 [2] 23 f2 [2] 3f f5 [2] 23 da }

  condition:
    any of them
}