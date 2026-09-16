rule TTP_XOR_QUAD_CurrentVersionRun_df88 {
  strings:
    $key_df88 = { 8c e7 [2] a8 e9 [2] 83 c5 [2] ad e7 [2] b9 fc [2] b6 e6 [2] a8 fb [2] aa fa [2] b1 fc [2] ad fb [2] b1 d4 }

  condition:
    any of them
}