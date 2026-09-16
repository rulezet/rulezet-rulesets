rule TTP_XOR_QUAD_CurrentVersionRun_0985 {
  strings:
    $key_0985 = { 5a ea [2] 7e e4 [2] 55 c8 [2] 7b ea [2] 6f f1 [2] 60 eb [2] 7e f6 [2] 7c f7 [2] 67 f1 [2] 7b f6 [2] 67 d9 }

  condition:
    any of them
}