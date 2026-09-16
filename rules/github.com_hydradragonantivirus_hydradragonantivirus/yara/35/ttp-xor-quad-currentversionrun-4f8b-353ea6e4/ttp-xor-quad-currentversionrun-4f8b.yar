rule TTP_XOR_QUAD_CurrentVersionRun_4f8b {
  strings:
    $key_4f8b = { 1c e4 [2] 38 ea [2] 13 c6 [2] 3d e4 [2] 29 ff [2] 26 e5 [2] 38 f8 [2] 3a f9 [2] 21 ff [2] 3d f8 [2] 21 d7 }

  condition:
    any of them
}