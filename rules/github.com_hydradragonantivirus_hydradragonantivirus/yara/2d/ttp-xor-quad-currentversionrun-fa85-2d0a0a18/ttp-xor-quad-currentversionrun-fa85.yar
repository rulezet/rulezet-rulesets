rule TTP_XOR_QUAD_CurrentVersionRun_fa85 {
  strings:
    $key_fa85 = { a9 ea [2] 8d e4 [2] a6 c8 [2] 88 ea [2] 9c f1 [2] 93 eb [2] 8d f6 [2] 8f f7 [2] 94 f1 [2] 88 f6 [2] 94 d9 }

  condition:
    any of them
}