rule TTP_XOR_QUAD_CurrentVersionRun_df2a {
  strings:
    $key_df2a = { 8c 45 [2] a8 4b [2] 83 67 [2] ad 45 [2] b9 5e [2] b6 44 [2] a8 59 [2] aa 58 [2] b1 5e [2] ad 59 [2] b1 76 }

  condition:
    any of them
}