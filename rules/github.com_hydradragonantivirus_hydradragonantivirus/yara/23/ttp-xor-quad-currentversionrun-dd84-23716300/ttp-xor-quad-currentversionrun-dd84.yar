rule TTP_XOR_QUAD_CurrentVersionRun_dd84 {
  strings:
    $key_dd84 = { 8e eb [2] aa e5 [2] 81 c9 [2] af eb [2] bb f0 [2] b4 ea [2] aa f7 [2] a8 f6 [2] b3 f0 [2] af f7 [2] b3 d8 }

  condition:
    any of them
}