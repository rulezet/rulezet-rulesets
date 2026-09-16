rule TTP_XOR_QUAD_CurrentVersionRun_df24 {
  strings:
    $key_df24 = { 8c 4b [2] a8 45 [2] 83 69 [2] ad 4b [2] b9 50 [2] b6 4a [2] a8 57 [2] aa 56 [2] b1 50 [2] ad 57 [2] b1 78 }

  condition:
    any of them
}