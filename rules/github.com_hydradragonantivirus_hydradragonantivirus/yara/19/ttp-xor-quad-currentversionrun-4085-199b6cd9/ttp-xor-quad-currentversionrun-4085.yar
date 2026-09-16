rule TTP_XOR_QUAD_CurrentVersionRun_4085 {
  strings:
    $key_4085 = { 13 ea [2] 37 e4 [2] 1c c8 [2] 32 ea [2] 26 f1 [2] 29 eb [2] 37 f6 [2] 35 f7 [2] 2e f1 [2] 32 f6 [2] 2e d9 }

  condition:
    any of them
}