rule TTP_XOR_QUAD_CurrentVersionRun_6b85 {
  strings:
    $key_6b85 = { 38 ea [2] 1c e4 [2] 37 c8 [2] 19 ea [2] 0d f1 [2] 02 eb [2] 1c f6 [2] 1e f7 [2] 05 f1 [2] 19 f6 [2] 05 d9 }

  condition:
    any of them
}