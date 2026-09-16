rule TTP_XOR_QUAD_CurrentVersionRun_5c9a {
  strings:
    $key_5c9a = { 0f f5 [2] 2b fb [2] 00 d7 [2] 2e f5 [2] 3a ee [2] 35 f4 [2] 2b e9 [2] 29 e8 [2] 32 ee [2] 2e e9 [2] 32 c6 }

  condition:
    any of them
}