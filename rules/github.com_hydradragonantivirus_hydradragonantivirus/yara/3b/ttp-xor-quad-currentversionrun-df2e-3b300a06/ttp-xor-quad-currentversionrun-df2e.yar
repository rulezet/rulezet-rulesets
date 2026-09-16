rule TTP_XOR_QUAD_CurrentVersionRun_df2e {
  strings:
    $key_df2e = { 8c 41 [2] a8 4f [2] 83 63 [2] ad 41 [2] b9 5a [2] b6 40 [2] a8 5d [2] aa 5c [2] b1 5a [2] ad 5d [2] b1 72 }

  condition:
    any of them
}