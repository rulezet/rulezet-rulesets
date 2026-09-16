rule TTP_XOR_QUAD_CurrentVersionRun_df1f {
  strings:
    $key_df1f = { 8c 70 [2] a8 7e [2] 83 52 [2] ad 70 [2] b9 6b [2] b6 71 [2] a8 6c [2] aa 6d [2] b1 6b [2] ad 6c [2] b1 43 }

  condition:
    any of them
}