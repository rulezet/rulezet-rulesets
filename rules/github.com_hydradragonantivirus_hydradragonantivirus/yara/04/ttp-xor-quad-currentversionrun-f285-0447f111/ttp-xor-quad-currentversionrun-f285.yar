rule TTP_XOR_QUAD_CurrentVersionRun_f285 {
  strings:
    $key_f285 = { a1 ea [2] 85 e4 [2] ae c8 [2] 80 ea [2] 94 f1 [2] 9b eb [2] 85 f6 [2] 87 f7 [2] 9c f1 [2] 80 f6 [2] 9c d9 }

  condition:
    any of them
}