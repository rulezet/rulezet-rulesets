rule TTP_XOR_QUAD_CurrentVersionRun_df07 {
  strings:
    $key_df07 = { 8c 68 [2] a8 66 [2] 83 4a [2] ad 68 [2] b9 73 [2] b6 69 [2] a8 74 [2] aa 75 [2] b1 73 [2] ad 74 [2] b1 5b }

  condition:
    any of them
}