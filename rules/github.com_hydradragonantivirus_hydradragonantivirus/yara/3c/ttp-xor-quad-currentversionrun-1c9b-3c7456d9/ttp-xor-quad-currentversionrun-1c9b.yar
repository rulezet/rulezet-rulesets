rule TTP_XOR_QUAD_CurrentVersionRun_1c9b {
  strings:
    $key_1c9b = { 4f f4 [2] 6b fa [2] 40 d6 [2] 6e f4 [2] 7a ef [2] 75 f5 [2] 6b e8 [2] 69 e9 [2] 72 ef [2] 6e e8 [2] 72 c7 }

  condition:
    any of them
}