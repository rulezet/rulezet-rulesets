rule TTP_XOR_QUAD_CurrentVersionRun_fc8b {
  strings:
    $key_fc8b = { af e4 [2] 8b ea [2] a0 c6 [2] 8e e4 [2] 9a ff [2] 95 e5 [2] 8b f8 [2] 89 f9 [2] 92 ff [2] 8e f8 [2] 92 d7 }

  condition:
    any of them
}