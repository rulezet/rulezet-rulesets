rule TTP_XOR_QUAD_CurrentVersionRun_f085 {
  strings:
    $key_f085 = { a3 ea [2] 87 e4 [2] ac c8 [2] 82 ea [2] 96 f1 [2] 99 eb [2] 87 f6 [2] 85 f7 [2] 9e f1 [2] 82 f6 [2] 9e d9 }

  condition:
    any of them
}