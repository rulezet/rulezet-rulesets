rule TTP_XOR_QUAD_CurrentVersionRun_1a8b {
  strings:
    $key_1a8b = { 49 e4 [2] 6d ea [2] 46 c6 [2] 68 e4 [2] 7c ff [2] 73 e5 [2] 6d f8 [2] 6f f9 [2] 74 ff [2] 68 f8 [2] 74 d7 }

  condition:
    any of them
}