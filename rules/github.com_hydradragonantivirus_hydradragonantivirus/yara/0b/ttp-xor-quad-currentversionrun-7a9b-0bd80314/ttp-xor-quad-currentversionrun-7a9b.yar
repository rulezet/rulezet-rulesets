rule TTP_XOR_QUAD_CurrentVersionRun_7a9b {
  strings:
    $key_7a9b = { 29 f4 [2] 0d fa [2] 26 d6 [2] 08 f4 [2] 1c ef [2] 13 f5 [2] 0d e8 [2] 0f e9 [2] 14 ef [2] 08 e8 [2] 14 c7 }

  condition:
    any of them
}