rule TTP_XOR_QUAD_CurrentVersionRun_4c8b {
  strings:
    $key_4c8b = { 1f e4 [2] 3b ea [2] 10 c6 [2] 3e e4 [2] 2a ff [2] 25 e5 [2] 3b f8 [2] 39 f9 [2] 22 ff [2] 3e f8 [2] 22 d7 }

  condition:
    any of them
}