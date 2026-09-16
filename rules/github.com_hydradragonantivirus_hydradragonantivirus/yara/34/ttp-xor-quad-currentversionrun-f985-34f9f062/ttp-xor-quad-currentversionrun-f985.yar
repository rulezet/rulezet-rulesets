rule TTP_XOR_QUAD_CurrentVersionRun_f985 {
  strings:
    $key_f985 = { aa ea [2] 8e e4 [2] a5 c8 [2] 8b ea [2] 9f f1 [2] 90 eb [2] 8e f6 [2] 8c f7 [2] 97 f1 [2] 8b f6 [2] 97 d9 }

  condition:
    any of them
}