rule TTP_XOR_QUAD_CurrentVersionRun_1e8b {
  strings:
    $key_1e8b = { 4d e4 [2] 69 ea [2] 42 c6 [2] 6c e4 [2] 78 ff [2] 77 e5 [2] 69 f8 [2] 6b f9 [2] 70 ff [2] 6c f8 [2] 70 d7 }

  condition:
    any of them
}