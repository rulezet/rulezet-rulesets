rule TTP_XOR_QUAD_CurrentVersionRun_219b {
  strings:
    $key_219b = { 72 f4 [2] 56 fa [2] 7d d6 [2] 53 f4 [2] 47 ef [2] 48 f5 [2] 56 e8 [2] 54 e9 [2] 4f ef [2] 53 e8 [2] 4f c7 }

  condition:
    any of them
}