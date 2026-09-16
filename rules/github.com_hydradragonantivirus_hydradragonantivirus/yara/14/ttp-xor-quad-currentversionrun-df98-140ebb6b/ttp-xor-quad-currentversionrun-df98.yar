rule TTP_XOR_QUAD_CurrentVersionRun_df98 {
  strings:
    $key_df98 = { 8c f7 [2] a8 f9 [2] 83 d5 [2] ad f7 [2] b9 ec [2] b6 f6 [2] a8 eb [2] aa ea [2] b1 ec [2] ad eb [2] b1 c4 }

  condition:
    any of them
}