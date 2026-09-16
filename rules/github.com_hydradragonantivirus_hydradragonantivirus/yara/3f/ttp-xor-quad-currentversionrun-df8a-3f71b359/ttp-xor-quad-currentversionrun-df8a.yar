rule TTP_XOR_QUAD_CurrentVersionRun_df8a {
  strings:
    $key_df8a = { 8c e5 [2] a8 eb [2] 83 c7 [2] ad e5 [2] b9 fe [2] b6 e4 [2] a8 f9 [2] aa f8 [2] b1 fe [2] ad f9 [2] b1 d6 }

  condition:
    any of them
}