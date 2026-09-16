rule TTP_XOR_QUAD_CurrentVersionRun_1a9b {
  strings:
    $key_1a9b = { 49 f4 [2] 6d fa [2] 46 d6 [2] 68 f4 [2] 7c ef [2] 73 f5 [2] 6d e8 [2] 6f e9 [2] 74 ef [2] 68 e8 [2] 74 c7 }

  condition:
    any of them
}