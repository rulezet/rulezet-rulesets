rule TTP_XOR_QUAD_CurrentVersionRun_df25 {
  strings:
    $key_df25 = { 8c 4a [2] a8 44 [2] 83 68 [2] ad 4a [2] b9 51 [2] b6 4b [2] a8 56 [2] aa 57 [2] b1 51 [2] ad 56 [2] b1 79 }

  condition:
    any of them
}