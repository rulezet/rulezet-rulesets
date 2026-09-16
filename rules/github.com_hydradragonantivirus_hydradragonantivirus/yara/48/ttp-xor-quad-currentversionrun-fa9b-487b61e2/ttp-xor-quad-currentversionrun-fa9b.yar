rule TTP_XOR_QUAD_CurrentVersionRun_fa9b {
  strings:
    $key_fa9b = { a9 f4 [2] 8d fa [2] a6 d6 [2] 88 f4 [2] 9c ef [2] 93 f5 [2] 8d e8 [2] 8f e9 [2] 94 ef [2] 88 e8 [2] 94 c7 }

  condition:
    any of them
}