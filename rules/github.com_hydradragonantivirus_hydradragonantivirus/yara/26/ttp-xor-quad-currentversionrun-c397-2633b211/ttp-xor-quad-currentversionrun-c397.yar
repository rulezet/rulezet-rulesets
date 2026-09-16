rule TTP_XOR_QUAD_CurrentVersionRun_c397 {
  strings:
    $key_c397 = { 90 f8 [2] b4 f6 [2] 9f da [2] b1 f8 [2] a5 e3 [2] aa f9 [2] b4 e4 [2] b6 e5 [2] ad e3 [2] b1 e4 [2] ad cb }

  condition:
    any of them
}