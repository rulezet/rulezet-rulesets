rule TTP_XOR_QUAD_CurrentVersionRun_7c9b {
  strings:
    $key_7c9b = { 2f f4 [2] 0b fa [2] 20 d6 [2] 0e f4 [2] 1a ef [2] 15 f5 [2] 0b e8 [2] 09 e9 [2] 12 ef [2] 0e e8 [2] 12 c7 }

  condition:
    any of them
}