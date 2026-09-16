rule TTP_XOR_QUAD_CurrentVersionRun_e985 {
  strings:
    $key_e985 = { ba ea [2] 9e e4 [2] b5 c8 [2] 9b ea [2] 8f f1 [2] 80 eb [2] 9e f6 [2] 9c f7 [2] 87 f1 [2] 9b f6 [2] 87 d9 }

  condition:
    any of them
}