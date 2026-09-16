rule TTP_XOR_QUAD_CurrentVersionRun_df95 {
  strings:
    $key_df95 = { 8c fa [2] a8 f4 [2] 83 d8 [2] ad fa [2] b9 e1 [2] b6 fb [2] a8 e6 [2] aa e7 [2] b1 e1 [2] ad e6 [2] b1 c9 }

  condition:
    any of them
}