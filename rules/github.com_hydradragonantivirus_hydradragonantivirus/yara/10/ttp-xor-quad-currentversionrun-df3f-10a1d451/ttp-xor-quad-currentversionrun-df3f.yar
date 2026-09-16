rule TTP_XOR_QUAD_CurrentVersionRun_df3f {
  strings:
    $key_df3f = { 8c 50 [2] a8 5e [2] 83 72 [2] ad 50 [2] b9 4b [2] b6 51 [2] a8 4c [2] aa 4d [2] b1 4b [2] ad 4c [2] b1 63 }

  condition:
    any of them
}