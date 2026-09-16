rule TTP_XOR_QUAD_CurrentVersionRun_df90 {
  strings:
    $key_df90 = { 8c ff [2] a8 f1 [2] 83 dd [2] ad ff [2] b9 e4 [2] b6 fe [2] a8 e3 [2] aa e2 [2] b1 e4 [2] ad e3 [2] b1 cc }

  condition:
    any of them
}