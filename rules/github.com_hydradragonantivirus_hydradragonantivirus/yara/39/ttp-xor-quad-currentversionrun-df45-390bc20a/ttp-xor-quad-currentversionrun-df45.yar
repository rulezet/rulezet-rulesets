rule TTP_XOR_QUAD_CurrentVersionRun_df45 {
  strings:
    $key_df45 = { 8c 2a [2] a8 24 [2] 83 08 [2] ad 2a [2] b9 31 [2] b6 2b [2] a8 36 [2] aa 37 [2] b1 31 [2] ad 36 [2] b1 19 }

  condition:
    any of them
}