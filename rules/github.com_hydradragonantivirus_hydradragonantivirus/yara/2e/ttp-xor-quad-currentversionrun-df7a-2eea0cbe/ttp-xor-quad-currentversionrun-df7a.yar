rule TTP_XOR_QUAD_CurrentVersionRun_df7a {
  strings:
    $key_df7a = { 8c 15 [2] a8 1b [2] 83 37 [2] ad 15 [2] b9 0e [2] b6 14 [2] a8 09 [2] aa 08 [2] b1 0e [2] ad 09 [2] b1 26 }

  condition:
    any of them
}