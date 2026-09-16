rule TTP_XOR_QUAD_CurrentVersionRun_df1b {
  strings:
    $key_df1b = { 8c 74 [2] a8 7a [2] 83 56 [2] ad 74 [2] b9 6f [2] b6 75 [2] a8 68 [2] aa 69 [2] b1 6f [2] ad 68 [2] b1 47 }

  condition:
    any of them
}