rule TTP_XOR_QUAD_CurrentVersionRun_df09 {
  strings:
    $key_df09 = { 8c 66 [2] a8 68 [2] 83 44 [2] ad 66 [2] b9 7d [2] b6 67 [2] a8 7a [2] aa 7b [2] b1 7d [2] ad 7a [2] b1 55 }

  condition:
    any of them
}