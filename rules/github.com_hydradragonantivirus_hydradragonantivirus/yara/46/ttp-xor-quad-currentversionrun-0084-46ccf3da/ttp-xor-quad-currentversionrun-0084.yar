rule TTP_XOR_QUAD_CurrentVersionRun_0084 {
  strings:
    $key_0084 = { 53 eb [2] 77 e5 [2] 5c c9 [2] 72 eb [2] 66 f0 [2] 69 ea [2] 77 f7 [2] 75 f6 [2] 6e f0 [2] 72 f7 [2] 6e d8 }

  condition:
    any of them
}