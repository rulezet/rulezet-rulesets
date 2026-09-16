rule TTP_XOR_QUAD_CurrentVersionRun_5cd6 {
  strings:
    $key_5cd6 = { 0f b9 [2] 2b b7 [2] 00 9b [2] 2e b9 [2] 3a a2 [2] 35 b8 [2] 2b a5 [2] 29 a4 [2] 32 a2 [2] 2e a5 [2] 32 8a }

  condition:
    any of them
}