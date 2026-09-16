rule TTP_XOR_QUAD_CurrentVersionRun_df18 {
  strings:
    $key_df18 = { 8c 77 [2] a8 79 [2] 83 55 [2] ad 77 [2] b9 6c [2] b6 76 [2] a8 6b [2] aa 6a [2] b1 6c [2] ad 6b [2] b1 44 }

  condition:
    any of them
}