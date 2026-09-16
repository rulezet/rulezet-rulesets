rule TTP_XOR_QUAD_CurrentVersionRun_df3b {
  strings:
    $key_df3b = { 8c 54 [2] a8 5a [2] 83 76 [2] ad 54 [2] b9 4f [2] b6 55 [2] a8 48 [2] aa 49 [2] b1 4f [2] ad 48 [2] b1 67 }

  condition:
    any of them
}