rule TTP_XOR_QUAD_CurrentVersionRun_0c8b {
  strings:
    $key_0c8b = { 5f e4 [2] 7b ea [2] 50 c6 [2] 7e e4 [2] 6a ff [2] 65 e5 [2] 7b f8 [2] 79 f9 [2] 62 ff [2] 7e f8 [2] 62 d7 }

  condition:
    any of them
}