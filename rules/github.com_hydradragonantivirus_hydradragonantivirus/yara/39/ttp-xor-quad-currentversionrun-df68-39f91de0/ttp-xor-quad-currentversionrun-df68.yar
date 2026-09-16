rule TTP_XOR_QUAD_CurrentVersionRun_df68 {
  strings:
    $key_df68 = { 8c 07 [2] a8 09 [2] 83 25 [2] ad 07 [2] b9 1c [2] b6 06 [2] a8 1b [2] aa 1a [2] b1 1c [2] ad 1b [2] b1 34 }

  condition:
    any of them
}