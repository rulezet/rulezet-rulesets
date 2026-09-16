rule TTP_XOR_QUAD_CurrentVersionRun_5c97 {
  strings:
    $key_5c97 = { 0f f8 [2] 2b f6 [2] 00 da [2] 2e f8 [2] 3a e3 [2] 35 f9 [2] 2b e4 [2] 29 e5 [2] 32 e3 [2] 2e e4 [2] 32 cb }

  condition:
    any of them
}