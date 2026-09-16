rule TTP_XOR_QUAD_CurrentVersionRun_df79 {
  strings:
    $key_df79 = { 8c 16 [2] a8 18 [2] 83 34 [2] ad 16 [2] b9 0d [2] b6 17 [2] a8 0a [2] aa 0b [2] b1 0d [2] ad 0a [2] b1 25 }

  condition:
    any of them
}