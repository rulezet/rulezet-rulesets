rule TTP_XOR_QUAD_CurrentVersionRun_df55 {
  strings:
    $key_df55 = { 8c 3a [2] a8 34 [2] 83 18 [2] ad 3a [2] b9 21 [2] b6 3b [2] a8 26 [2] aa 27 [2] b1 21 [2] ad 26 [2] b1 09 }

  condition:
    any of them
}