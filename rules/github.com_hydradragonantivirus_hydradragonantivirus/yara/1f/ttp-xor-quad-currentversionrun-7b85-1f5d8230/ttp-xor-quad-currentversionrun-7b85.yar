rule TTP_XOR_QUAD_CurrentVersionRun_7b85 {
  strings:
    $key_7b85 = { 28 ea [2] 0c e4 [2] 27 c8 [2] 09 ea [2] 1d f1 [2] 12 eb [2] 0c f6 [2] 0e f7 [2] 15 f1 [2] 09 f6 [2] 15 d9 }

  condition:
    any of them
}