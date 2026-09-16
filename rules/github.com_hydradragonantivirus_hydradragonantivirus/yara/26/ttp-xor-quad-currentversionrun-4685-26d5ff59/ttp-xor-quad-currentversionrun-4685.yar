rule TTP_XOR_QUAD_CurrentVersionRun_4685 {
  strings:
    $key_4685 = { 15 ea [2] 31 e4 [2] 1a c8 [2] 34 ea [2] 20 f1 [2] 2f eb [2] 31 f6 [2] 33 f7 [2] 28 f1 [2] 34 f6 [2] 28 d9 }

  condition:
    any of them
}