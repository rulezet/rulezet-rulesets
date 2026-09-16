rule TTP_XOR_QUAD_CurrentVersionRun_5c85 {
  strings:
    $key_5c85 = { 0f ea [2] 2b e4 [2] 00 c8 [2] 2e ea [2] 3a f1 [2] 35 eb [2] 2b f6 [2] 29 f7 [2] 32 f1 [2] 2e f6 [2] 32 d9 }

  condition:
    any of them
}