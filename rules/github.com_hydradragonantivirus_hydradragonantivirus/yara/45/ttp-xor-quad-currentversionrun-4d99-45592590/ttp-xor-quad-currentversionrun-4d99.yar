rule TTP_XOR_QUAD_CurrentVersionRun_4d99 {
  strings:
    $key_4d99 = { 1e f6 [2] 3a f8 [2] 11 d4 [2] 3f f6 [2] 2b ed [2] 24 f7 [2] 3a ea [2] 38 eb [2] 23 ed [2] 3f ea [2] 23 c5 }

  condition:
    any of them
}