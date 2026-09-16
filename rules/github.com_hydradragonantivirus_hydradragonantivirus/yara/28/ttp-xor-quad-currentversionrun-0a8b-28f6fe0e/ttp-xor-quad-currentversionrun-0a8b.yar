rule TTP_XOR_QUAD_CurrentVersionRun_0a8b {
  strings:
    $key_0a8b = { 59 e4 [2] 7d ea [2] 56 c6 [2] 78 e4 [2] 6c ff [2] 63 e5 [2] 7d f8 [2] 7f f9 [2] 64 ff [2] 78 f8 [2] 64 d7 }

  condition:
    any of them
}