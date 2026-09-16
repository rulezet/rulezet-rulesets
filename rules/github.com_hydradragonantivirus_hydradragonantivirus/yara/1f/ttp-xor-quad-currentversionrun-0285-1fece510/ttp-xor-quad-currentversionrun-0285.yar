rule TTP_XOR_QUAD_CurrentVersionRun_0285 {
  strings:
    $key_0285 = { 51 ea [2] 75 e4 [2] 5e c8 [2] 70 ea [2] 64 f1 [2] 6b eb [2] 75 f6 [2] 77 f7 [2] 6c f1 [2] 70 f6 [2] 6c d9 }

  condition:
    any of them
}