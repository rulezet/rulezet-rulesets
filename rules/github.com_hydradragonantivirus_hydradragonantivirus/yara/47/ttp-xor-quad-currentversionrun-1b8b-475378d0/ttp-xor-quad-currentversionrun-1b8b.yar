rule TTP_XOR_QUAD_CurrentVersionRun_1b8b {
  strings:
    $key_1b8b = { 48 e4 [2] 6c ea [2] 47 c6 [2] 69 e4 [2] 7d ff [2] 72 e5 [2] 6c f8 [2] 6e f9 [2] 75 ff [2] 69 f8 [2] 75 d7 }

  condition:
    any of them
}