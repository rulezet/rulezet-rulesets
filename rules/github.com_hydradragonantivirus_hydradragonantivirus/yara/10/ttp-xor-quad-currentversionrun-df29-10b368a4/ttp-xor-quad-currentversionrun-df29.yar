rule TTP_XOR_QUAD_CurrentVersionRun_df29 {
  strings:
    $key_df29 = { 8c 46 [2] a8 48 [2] 83 64 [2] ad 46 [2] b9 5d [2] b6 47 [2] a8 5a [2] aa 5b [2] b1 5d [2] ad 5a [2] b1 75 }

  condition:
    any of them
}