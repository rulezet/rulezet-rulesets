rule TTP_XOR_QUAD_CurrentVersionRun_fa84 {
  strings:
    $key_fa84 = { a9 eb [2] 8d e5 [2] a6 c9 [2] 88 eb [2] 9c f0 [2] 93 ea [2] 8d f7 [2] 8f f6 [2] 94 f0 [2] 88 f7 [2] 94 d8 }

  condition:
    any of them
}