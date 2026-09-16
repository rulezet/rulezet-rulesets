rule TTP_XOR_QUAD_CurrentVersionRun_c487 {
  strings:
    $key_c487 = { 97 e8 [2] b3 e6 [2] 98 ca [2] b6 e8 [2] a2 f3 [2] ad e9 [2] b3 f4 [2] b1 f5 [2] aa f3 [2] b6 f4 [2] aa db }

  condition:
    any of them
}