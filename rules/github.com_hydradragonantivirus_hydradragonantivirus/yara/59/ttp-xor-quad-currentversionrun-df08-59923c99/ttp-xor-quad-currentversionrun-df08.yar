rule TTP_XOR_QUAD_CurrentVersionRun_df08 {
  strings:
    $key_df08 = { 8c 67 [2] a8 69 [2] 83 45 [2] ad 67 [2] b9 7c [2] b6 66 [2] a8 7b [2] aa 7a [2] b1 7c [2] ad 7b [2] b1 54 }

  condition:
    any of them
}