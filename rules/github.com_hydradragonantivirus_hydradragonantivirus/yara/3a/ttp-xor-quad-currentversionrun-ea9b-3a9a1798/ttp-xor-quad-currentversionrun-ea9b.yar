rule TTP_XOR_QUAD_CurrentVersionRun_ea9b {
  strings:
    $key_ea9b = { b9 f4 [2] 9d fa [2] b6 d6 [2] 98 f4 [2] 8c ef [2] 83 f5 [2] 9d e8 [2] 9f e9 [2] 84 ef [2] 98 e8 [2] 84 c7 }

  condition:
    any of them
}