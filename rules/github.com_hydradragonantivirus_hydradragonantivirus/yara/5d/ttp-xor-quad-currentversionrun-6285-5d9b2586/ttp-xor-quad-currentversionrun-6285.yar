rule TTP_XOR_QUAD_CurrentVersionRun_6285 {
  strings:
    $key_6285 = { 31 ea [2] 15 e4 [2] 3e c8 [2] 10 ea [2] 04 f1 [2] 0b eb [2] 15 f6 [2] 17 f7 [2] 0c f1 [2] 10 f6 [2] 0c d9 }

  condition:
    any of them
}