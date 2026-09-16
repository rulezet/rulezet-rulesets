rule TTP_XOR_QUAD_CurrentVersionRun_ff85 {
  strings:
    $key_ff85 = { ac ea [2] 88 e4 [2] a3 c8 [2] 8d ea [2] 99 f1 [2] 96 eb [2] 88 f6 [2] 8a f7 [2] 91 f1 [2] 8d f6 [2] 91 d9 }

  condition:
    any of them
}