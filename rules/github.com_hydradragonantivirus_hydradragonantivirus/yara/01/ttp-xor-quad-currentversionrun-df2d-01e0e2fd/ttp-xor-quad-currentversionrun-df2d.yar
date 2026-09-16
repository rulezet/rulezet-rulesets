rule TTP_XOR_QUAD_CurrentVersionRun_df2d {
  strings:
    $key_df2d = { 8c 42 [2] a8 4c [2] 83 60 [2] ad 42 [2] b9 59 [2] b6 43 [2] a8 5e [2] aa 5f [2] b1 59 [2] ad 5e [2] b1 71 }

  condition:
    any of them
}