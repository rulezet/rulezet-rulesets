rule TTP_XOR_QUAD_CurrentVersionRun_0085 {
  strings:
    $key_0085 = { 53 ea [2] 77 e4 [2] 5c c8 [2] 72 ea [2] 66 f1 [2] 69 eb [2] 77 f6 [2] 75 f7 [2] 6e f1 [2] 72 f6 [2] 6e d9 }

  condition:
    any of them
}