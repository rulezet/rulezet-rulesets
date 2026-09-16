rule TTP_XOR_QUAD_CurrentVersionRun_4284 {
  strings:
    $key_4284 = { 11 eb [2] 35 e5 [2] 1e c9 [2] 30 eb [2] 24 f0 [2] 2b ea [2] 35 f7 [2] 37 f6 [2] 2c f0 [2] 30 f7 [2] 2c d8 }

  condition:
    any of them
}