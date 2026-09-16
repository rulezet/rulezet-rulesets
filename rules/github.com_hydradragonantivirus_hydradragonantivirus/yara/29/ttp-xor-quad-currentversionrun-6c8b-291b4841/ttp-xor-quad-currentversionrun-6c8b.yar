rule TTP_XOR_QUAD_CurrentVersionRun_6c8b {
  strings:
    $key_6c8b = { 3f e4 [2] 1b ea [2] 30 c6 [2] 1e e4 [2] 0a ff [2] 05 e5 [2] 1b f8 [2] 19 f9 [2] 02 ff [2] 1e f8 [2] 02 d7 }

  condition:
    any of them
}