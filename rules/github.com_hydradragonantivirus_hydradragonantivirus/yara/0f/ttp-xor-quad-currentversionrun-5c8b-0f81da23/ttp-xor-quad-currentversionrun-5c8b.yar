rule TTP_XOR_QUAD_CurrentVersionRun_5c8b {
  strings:
    $key_5c8b = { 0f e4 [2] 2b ea [2] 00 c6 [2] 2e e4 [2] 3a ff [2] 35 e5 [2] 2b f8 [2] 29 f9 [2] 32 ff [2] 2e f8 [2] 32 d7 }

  condition:
    any of them
}