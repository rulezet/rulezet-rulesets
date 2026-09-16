rule TTP_XOR_QUAD_CurrentVersionRun_fb8b {
  strings:
    $key_fb8b = { a8 e4 [2] 8c ea [2] a7 c6 [2] 89 e4 [2] 9d ff [2] 92 e5 [2] 8c f8 [2] 8e f9 [2] 95 ff [2] 89 f8 [2] 95 d7 }

  condition:
    any of them
}