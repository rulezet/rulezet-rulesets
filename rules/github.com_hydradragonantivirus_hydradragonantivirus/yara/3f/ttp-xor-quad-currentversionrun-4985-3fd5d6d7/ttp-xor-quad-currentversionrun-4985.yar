rule TTP_XOR_QUAD_CurrentVersionRun_4985 {
  strings:
    $key_4985 = { 1a ea [2] 3e e4 [2] 15 c8 [2] 3b ea [2] 2f f1 [2] 20 eb [2] 3e f6 [2] 3c f7 [2] 27 f1 [2] 3b f6 [2] 27 d9 }

  condition:
    any of them
}