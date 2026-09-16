rule TTP_XOR_QUAD_CurrentVersionRun_119b {
  strings:
    $key_119b = { 42 f4 [2] 66 fa [2] 4d d6 [2] 63 f4 [2] 77 ef [2] 78 f5 [2] 66 e8 [2] 64 e9 [2] 7f ef [2] 63 e8 [2] 7f c7 }

  condition:
    any of them
}