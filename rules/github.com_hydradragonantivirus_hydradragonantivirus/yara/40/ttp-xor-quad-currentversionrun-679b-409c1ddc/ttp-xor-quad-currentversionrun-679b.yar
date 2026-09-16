rule TTP_XOR_QUAD_CurrentVersionRun_679b {
  strings:
    $key_679b = { 34 f4 [2] 10 fa [2] 3b d6 [2] 15 f4 [2] 01 ef [2] 0e f5 [2] 10 e8 [2] 12 e9 [2] 09 ef [2] 15 e8 [2] 09 c7 }

  condition:
    any of them
}