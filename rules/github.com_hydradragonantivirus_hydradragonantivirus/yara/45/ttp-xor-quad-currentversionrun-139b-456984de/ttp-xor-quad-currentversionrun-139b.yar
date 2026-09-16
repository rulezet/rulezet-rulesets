rule TTP_XOR_QUAD_CurrentVersionRun_139b {
  strings:
    $key_139b = { 40 f4 [2] 64 fa [2] 4f d6 [2] 61 f4 [2] 75 ef [2] 7a f5 [2] 64 e8 [2] 66 e9 [2] 7d ef [2] 61 e8 [2] 7d c7 }

  condition:
    any of them
}