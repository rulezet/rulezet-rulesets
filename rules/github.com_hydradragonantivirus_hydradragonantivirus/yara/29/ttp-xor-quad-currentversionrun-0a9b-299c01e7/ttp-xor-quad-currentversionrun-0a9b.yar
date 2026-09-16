rule TTP_XOR_QUAD_CurrentVersionRun_0a9b {
  strings:
    $key_0a9b = { 59 f4 [2] 7d fa [2] 56 d6 [2] 78 f4 [2] 6c ef [2] 63 f5 [2] 7d e8 [2] 7f e9 [2] 64 ef [2] 78 e8 [2] 64 c7 }

  condition:
    any of them
}