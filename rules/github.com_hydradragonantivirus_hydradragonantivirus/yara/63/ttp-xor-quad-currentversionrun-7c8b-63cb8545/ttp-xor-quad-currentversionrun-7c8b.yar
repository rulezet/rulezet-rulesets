rule TTP_XOR_QUAD_CurrentVersionRun_7c8b {
  strings:
    $key_7c8b = { 2f e4 [2] 0b ea [2] 20 c6 [2] 0e e4 [2] 1a ff [2] 15 e5 [2] 0b f8 [2] 09 f9 [2] 12 ff [2] 0e f8 [2] 12 d7 }

  condition:
    any of them
}