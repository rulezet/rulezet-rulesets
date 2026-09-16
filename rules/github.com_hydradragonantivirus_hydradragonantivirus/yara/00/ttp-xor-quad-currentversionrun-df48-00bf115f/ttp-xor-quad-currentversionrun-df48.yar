rule TTP_XOR_QUAD_CurrentVersionRun_df48 {
  strings:
    $key_df48 = { 8c 27 [2] a8 29 [2] 83 05 [2] ad 27 [2] b9 3c [2] b6 26 [2] a8 3b [2] aa 3a [2] b1 3c [2] ad 3b [2] b1 14 }

  condition:
    any of them
}