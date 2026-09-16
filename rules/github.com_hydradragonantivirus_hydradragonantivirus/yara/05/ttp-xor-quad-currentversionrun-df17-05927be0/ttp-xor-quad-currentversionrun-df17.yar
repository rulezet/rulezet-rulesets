rule TTP_XOR_QUAD_CurrentVersionRun_df17 {
  strings:
    $key_df17 = { 8c 78 [2] a8 76 [2] 83 5a [2] ad 78 [2] b9 63 [2] b6 79 [2] a8 64 [2] aa 65 [2] b1 63 [2] ad 64 [2] b1 4b }

  condition:
    any of them
}