rule TTP_XOR_QUAD_CurrentVersionRun_3d9b {
  strings:
    $key_3d9b = { 6e f4 [2] 4a fa [2] 61 d6 [2] 4f f4 [2] 5b ef [2] 54 f5 [2] 4a e8 [2] 48 e9 [2] 53 ef [2] 4f e8 [2] 53 c7 }

  condition:
    any of them
}