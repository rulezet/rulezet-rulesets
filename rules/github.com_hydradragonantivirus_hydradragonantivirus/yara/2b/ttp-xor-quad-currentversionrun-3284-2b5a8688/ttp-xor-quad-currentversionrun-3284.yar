rule TTP_XOR_QUAD_CurrentVersionRun_3284 {
  strings:
    $key_3284 = { 61 eb [2] 45 e5 [2] 6e c9 [2] 40 eb [2] 54 f0 [2] 5b ea [2] 45 f7 [2] 47 f6 [2] 5c f0 [2] 40 f7 [2] 5c d8 }

  condition:
    any of them
}