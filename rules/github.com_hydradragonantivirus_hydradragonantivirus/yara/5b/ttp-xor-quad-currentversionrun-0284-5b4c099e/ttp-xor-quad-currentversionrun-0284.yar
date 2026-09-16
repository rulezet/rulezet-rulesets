rule TTP_XOR_QUAD_CurrentVersionRun_0284 {
  strings:
    $key_0284 = { 51 eb [2] 75 e5 [2] 5e c9 [2] 70 eb [2] 64 f0 [2] 6b ea [2] 75 f7 [2] 77 f6 [2] 6c f0 [2] 70 f7 [2] 6c d8 }

  condition:
    any of them
}