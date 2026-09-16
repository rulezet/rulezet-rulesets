rule TTP_XOR_QUAD_CurrentVersionRun_2284 {
  strings:
    $key_2284 = { 71 eb [2] 55 e5 [2] 7e c9 [2] 50 eb [2] 44 f0 [2] 4b ea [2] 55 f7 [2] 57 f6 [2] 4c f0 [2] 50 f7 [2] 4c d8 }

  condition:
    any of them
}