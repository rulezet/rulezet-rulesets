rule TTP_XOR_QUAD_CurrentVersionRun_7b8b {
  strings:
    $key_7b8b = { 28 e4 [2] 0c ea [2] 27 c6 [2] 09 e4 [2] 1d ff [2] 12 e5 [2] 0c f8 [2] 0e f9 [2] 15 ff [2] 09 f8 [2] 15 d7 }

  condition:
    any of them
}