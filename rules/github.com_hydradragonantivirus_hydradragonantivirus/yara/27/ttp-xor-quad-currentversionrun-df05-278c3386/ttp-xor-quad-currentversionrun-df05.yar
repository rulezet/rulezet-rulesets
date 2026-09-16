rule TTP_XOR_QUAD_CurrentVersionRun_df05 {
  strings:
    $key_df05 = { 8c 6a [2] a8 64 [2] 83 48 [2] ad 6a [2] b9 71 [2] b6 6b [2] a8 76 [2] aa 77 [2] b1 71 [2] ad 76 [2] b1 59 }

  condition:
    any of them
}