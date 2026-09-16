rule TTP_XOR_QUAD_CurrentVersionRun_d88b {
  strings:
    $key_d88b = { 8b e4 [2] af ea [2] 84 c6 [2] aa e4 [2] be ff [2] b1 e5 [2] af f8 [2] ad f9 [2] b6 ff [2] aa f8 [2] b6 d7 }

  condition:
    any of them
}