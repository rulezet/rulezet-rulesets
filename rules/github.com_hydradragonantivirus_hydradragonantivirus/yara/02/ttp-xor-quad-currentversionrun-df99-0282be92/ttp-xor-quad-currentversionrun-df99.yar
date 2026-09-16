rule TTP_XOR_QUAD_CurrentVersionRun_df99 {
  strings:
    $key_df99 = { 8c f6 [2] a8 f8 [2] 83 d4 [2] ad f6 [2] b9 ed [2] b6 f7 [2] a8 ea [2] aa eb [2] b1 ed [2] ad ea [2] b1 c5 }

  condition:
    any of them
}