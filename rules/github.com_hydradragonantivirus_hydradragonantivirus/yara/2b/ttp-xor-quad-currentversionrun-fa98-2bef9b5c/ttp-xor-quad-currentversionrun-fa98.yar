rule TTP_XOR_QUAD_CurrentVersionRun_fa98 {
  strings:
    $key_fa98 = { a9 f7 [2] 8d f9 [2] a6 d5 [2] 88 f7 [2] 9c ec [2] 93 f6 [2] 8d eb [2] 8f ea [2] 94 ec [2] 88 eb [2] 94 c4 }

  condition:
    any of them
}