rule TTP_XOR_QUAD_CurrentVersionRun_df27 {
  strings:
    $key_df27 = { 8c 48 [2] a8 46 [2] 83 6a [2] ad 48 [2] b9 53 [2] b6 49 [2] a8 54 [2] aa 55 [2] b1 53 [2] ad 54 [2] b1 7b }

  condition:
    any of them
}