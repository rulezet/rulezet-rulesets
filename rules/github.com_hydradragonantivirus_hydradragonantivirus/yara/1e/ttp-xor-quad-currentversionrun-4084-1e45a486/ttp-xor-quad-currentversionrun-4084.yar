rule TTP_XOR_QUAD_CurrentVersionRun_4084 {
  strings:
    $key_4084 = { 13 eb [2] 37 e5 [2] 1c c9 [2] 32 eb [2] 26 f0 [2] 29 ea [2] 37 f7 [2] 35 f6 [2] 2e f0 [2] 32 f7 [2] 2e d8 }

  condition:
    any of them
}