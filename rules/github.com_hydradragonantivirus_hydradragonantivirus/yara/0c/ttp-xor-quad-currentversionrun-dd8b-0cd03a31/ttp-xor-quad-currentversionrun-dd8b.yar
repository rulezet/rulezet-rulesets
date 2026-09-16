rule TTP_XOR_QUAD_CurrentVersionRun_dd8b {
  strings:
    $key_dd8b = { 8e e4 [2] aa ea [2] 81 c6 [2] af e4 [2] bb ff [2] b4 e5 [2] aa f8 [2] a8 f9 [2] b3 ff [2] af f8 [2] b3 d7 }

  condition:
    any of them
}