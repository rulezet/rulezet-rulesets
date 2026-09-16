rule TTP_XOR_QUAD_CurrentVersionRun_1985 {
  strings:
    $key_1985 = { 4a ea [2] 6e e4 [2] 45 c8 [2] 6b ea [2] 7f f1 [2] 70 eb [2] 6e f6 [2] 6c f7 [2] 77 f1 [2] 6b f6 [2] 77 d9 }

  condition:
    any of them
}