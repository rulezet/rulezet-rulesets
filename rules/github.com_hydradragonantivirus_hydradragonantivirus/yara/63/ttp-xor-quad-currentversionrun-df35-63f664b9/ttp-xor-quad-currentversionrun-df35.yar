rule TTP_XOR_QUAD_CurrentVersionRun_df35 {
  strings:
    $key_df35 = { 8c 5a [2] a8 54 [2] 83 78 [2] ad 5a [2] b9 41 [2] b6 5b [2] a8 46 [2] aa 47 [2] b1 41 [2] ad 46 [2] b1 69 }

  condition:
    any of them
}