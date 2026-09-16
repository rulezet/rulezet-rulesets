rule TTP_XOR_QUAD_CurrentVersionRun_fc9b {
  strings:
    $key_fc9b = { af f4 [2] 8b fa [2] a0 d6 [2] 8e f4 [2] 9a ef [2] 95 f5 [2] 8b e8 [2] 89 e9 [2] 92 ef [2] 8e e8 [2] 92 c7 }

  condition:
    any of them
}