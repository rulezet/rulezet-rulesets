rule TTP_XOR_QUAD_CurrentVersionRun_2c8b {
  strings:
    $key_2c8b = { 7f e4 [2] 5b ea [2] 70 c6 [2] 5e e4 [2] 4a ff [2] 45 e5 [2] 5b f8 [2] 59 f9 [2] 42 ff [2] 5e f8 [2] 42 d7 }

  condition:
    any of them
}