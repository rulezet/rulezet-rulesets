rule TTP_XOR_QUAD_CurrentVersionRun_7a8b {
  strings:
    $key_7a8b = { 29 e4 [2] 0d ea [2] 26 c6 [2] 08 e4 [2] 1c ff [2] 13 e5 [2] 0d f8 [2] 0f f9 [2] 14 ff [2] 08 f8 [2] 14 d7 }

  condition:
    any of them
}