rule TTP_XOR_QUAD_CurrentVersionRun_5985 {
  strings:
    $key_5985 = { 0a ea [2] 2e e4 [2] 05 c8 [2] 2b ea [2] 3f f1 [2] 30 eb [2] 2e f6 [2] 2c f7 [2] 37 f1 [2] 2b f6 [2] 37 d9 }

  condition:
    any of them
}