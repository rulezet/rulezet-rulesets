rule TTP_XOR_QUAD_CurrentVersionRun_0e8b {
  strings:
    $key_0e8b = { 5d e4 [2] 79 ea [2] 52 c6 [2] 7c e4 [2] 68 ff [2] 67 e5 [2] 79 f8 [2] 7b f9 [2] 60 ff [2] 7c f8 [2] 60 d7 }

  condition:
    any of them
}