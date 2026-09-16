rule TTP_XOR_QUAD_CurrentVersionRun_4c9b {
  strings:
    $key_4c9b = { 1f f4 [2] 3b fa [2] 10 d6 [2] 3e f4 [2] 2a ef [2] 25 f5 [2] 3b e8 [2] 39 e9 [2] 22 ef [2] 3e e8 [2] 22 c7 }

  condition:
    any of them
}