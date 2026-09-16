rule TTP_XOR_QUAD_CurrentVersionRun_5285 {
  strings:
    $key_5285 = { 01 ea [2] 25 e4 [2] 0e c8 [2] 20 ea [2] 34 f1 [2] 3b eb [2] 25 f6 [2] 27 f7 [2] 3c f1 [2] 20 f6 [2] 3c d9 }

  condition:
    any of them
}