rule TTP_XOR_QUAD_CurrentVersionRun_df44 {
  strings:
    $key_df44 = { 8c 2b [2] a8 25 [2] 83 09 [2] ad 2b [2] b9 30 [2] b6 2a [2] a8 37 [2] aa 36 [2] b1 30 [2] ad 37 [2] b1 18 }

  condition:
    any of them
}