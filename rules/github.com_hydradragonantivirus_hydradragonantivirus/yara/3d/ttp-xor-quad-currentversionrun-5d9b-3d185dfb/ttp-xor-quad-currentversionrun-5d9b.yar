rule TTP_XOR_QUAD_CurrentVersionRun_5d9b {
  strings:
    $key_5d9b = { 0e f4 [2] 2a fa [2] 01 d6 [2] 2f f4 [2] 3b ef [2] 34 f5 [2] 2a e8 [2] 28 e9 [2] 33 ef [2] 2f e8 [2] 33 c7 }

  condition:
    any of them
}