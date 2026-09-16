rule TTP_XOR_QUAD_CurrentVersionRun_2c9b {
  strings:
    $key_2c9b = { 7f f4 [2] 5b fa [2] 70 d6 [2] 5e f4 [2] 4a ef [2] 45 f5 [2] 5b e8 [2] 59 e9 [2] 42 ef [2] 5e e8 [2] 42 c7 }

  condition:
    any of them
}