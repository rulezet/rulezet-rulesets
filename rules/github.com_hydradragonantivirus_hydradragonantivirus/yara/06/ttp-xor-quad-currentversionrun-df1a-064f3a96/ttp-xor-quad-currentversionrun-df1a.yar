rule TTP_XOR_QUAD_CurrentVersionRun_df1a {
  strings:
    $key_df1a = { 8c 75 [2] a8 7b [2] 83 57 [2] ad 75 [2] b9 6e [2] b6 74 [2] a8 69 [2] aa 68 [2] b1 6e [2] ad 69 [2] b1 46 }

  condition:
    any of them
}