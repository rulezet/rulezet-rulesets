rule TTP_XOR_QUAD_CurrentVersionRun_519b {
  strings:
    $key_519b = { 02 f4 [2] 26 fa [2] 0d d6 [2] 23 f4 [2] 37 ef [2] 38 f5 [2] 26 e8 [2] 24 e9 [2] 3f ef [2] 23 e8 [2] 3f c7 }

  condition:
    any of them
}