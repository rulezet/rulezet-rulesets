rule TTP_XOR_QUAD_CurrentVersionRun_3a9b {
  strings:
    $key_3a9b = { 69 f4 [2] 4d fa [2] 66 d6 [2] 48 f4 [2] 5c ef [2] 53 f5 [2] 4d e8 [2] 4f e9 [2] 54 ef [2] 48 e8 [2] 54 c7 }

  condition:
    any of them
}