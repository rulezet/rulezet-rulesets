rule TTP_XOR_QUAD_CurrentVersionRun_df84 {
  strings:
    $key_df84 = { 8c eb [2] a8 e5 [2] 83 c9 [2] ad eb [2] b9 f0 [2] b6 ea [2] a8 f7 [2] aa f6 [2] b1 f0 [2] ad f7 [2] b1 d8 }

  condition:
    any of them
}