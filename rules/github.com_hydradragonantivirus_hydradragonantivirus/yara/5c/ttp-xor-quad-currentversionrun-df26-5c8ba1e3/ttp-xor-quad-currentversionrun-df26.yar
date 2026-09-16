rule TTP_XOR_QUAD_CurrentVersionRun_df26 {
  strings:
    $key_df26 = { 8c 49 [2] a8 47 [2] 83 6b [2] ad 49 [2] b9 52 [2] b6 48 [2] a8 55 [2] aa 54 [2] b1 52 [2] ad 55 [2] b1 7a }

  condition:
    any of them
}