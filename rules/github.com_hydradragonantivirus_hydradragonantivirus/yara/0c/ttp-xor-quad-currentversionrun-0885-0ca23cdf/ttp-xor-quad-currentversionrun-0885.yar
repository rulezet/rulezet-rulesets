rule TTP_XOR_QUAD_CurrentVersionRun_0885 {
  strings:
    $key_0885 = { 5b ea [2] 7f e4 [2] 54 c8 [2] 7a ea [2] 6e f1 [2] 61 eb [2] 7f f6 [2] 7d f7 [2] 66 f1 [2] 7a f6 [2] 66 d9 }

  condition:
    any of them
}