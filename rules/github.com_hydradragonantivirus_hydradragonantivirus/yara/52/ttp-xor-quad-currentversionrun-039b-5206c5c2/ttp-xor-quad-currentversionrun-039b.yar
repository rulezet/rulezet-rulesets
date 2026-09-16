rule TTP_XOR_QUAD_CurrentVersionRun_039b {
  strings:
    $key_039b = { 50 f4 [2] 74 fa [2] 5f d6 [2] 71 f4 [2] 65 ef [2] 6a f5 [2] 74 e8 [2] 76 e9 [2] 6d ef [2] 71 e8 [2] 6d c7 }

  condition:
    any of them
}