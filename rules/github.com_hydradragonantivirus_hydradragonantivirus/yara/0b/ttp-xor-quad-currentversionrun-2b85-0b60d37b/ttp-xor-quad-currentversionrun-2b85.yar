rule TTP_XOR_QUAD_CurrentVersionRun_2b85 {
  strings:
    $key_2b85 = { 78 ea [2] 5c e4 [2] 77 c8 [2] 59 ea [2] 4d f1 [2] 42 eb [2] 5c f6 [2] 5e f7 [2] 45 f1 [2] 59 f6 [2] 45 d9 }

  condition:
    any of them
}