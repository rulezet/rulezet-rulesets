rule TTP_XOR_QUAD_CurrentVersionRun_689b {
  strings:
    $key_689b = { 3b f4 [2] 1f fa [2] 34 d6 [2] 1a f4 [2] 0e ef [2] 01 f5 [2] 1f e8 [2] 1d e9 [2] 06 ef [2] 1a e8 [2] 06 c7 }

  condition:
    any of them
}