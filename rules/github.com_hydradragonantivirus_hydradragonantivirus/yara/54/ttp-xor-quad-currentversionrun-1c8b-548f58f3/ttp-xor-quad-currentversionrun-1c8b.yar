rule TTP_XOR_QUAD_CurrentVersionRun_1c8b {
  strings:
    $key_1c8b = { 4f e4 [2] 6b ea [2] 40 c6 [2] 6e e4 [2] 7a ff [2] 75 e5 [2] 6b f8 [2] 69 f9 [2] 72 ff [2] 6e f8 [2] 72 d7 }

  condition:
    any of them
}