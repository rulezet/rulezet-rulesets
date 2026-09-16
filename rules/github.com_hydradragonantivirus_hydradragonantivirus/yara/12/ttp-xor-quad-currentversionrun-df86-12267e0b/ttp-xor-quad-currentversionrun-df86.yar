rule TTP_XOR_QUAD_CurrentVersionRun_df86 {
  strings:
    $key_df86 = { 8c e9 [2] a8 e7 [2] 83 cb [2] ad e9 [2] b9 f2 [2] b6 e8 [2] a8 f5 [2] aa f4 [2] b1 f2 [2] ad f5 [2] b1 da }

  condition:
    any of them
}