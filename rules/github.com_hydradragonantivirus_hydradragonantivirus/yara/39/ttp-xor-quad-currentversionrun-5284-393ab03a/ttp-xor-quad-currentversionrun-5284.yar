rule TTP_XOR_QUAD_CurrentVersionRun_5284 {
  strings:
    $key_5284 = { 01 eb [2] 25 e5 [2] 0e c9 [2] 20 eb [2] 34 f0 [2] 3b ea [2] 25 f7 [2] 27 f6 [2] 3c f0 [2] 20 f7 [2] 3c d8 }

  condition:
    any of them
}