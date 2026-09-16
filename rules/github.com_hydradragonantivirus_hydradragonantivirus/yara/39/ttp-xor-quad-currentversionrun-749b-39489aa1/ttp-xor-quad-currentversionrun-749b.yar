rule TTP_XOR_QUAD_CurrentVersionRun_749b {
  strings:
    $key_749b = { 27 f4 [2] 03 fa [2] 28 d6 [2] 06 f4 [2] 12 ef [2] 1d f5 [2] 03 e8 [2] 01 e9 [2] 1a ef [2] 06 e8 [2] 1a c7 }

  condition:
    any of them
}