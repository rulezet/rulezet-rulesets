rule TTP_XOR_QUAD_CurrentVersionRun_549b {
  strings:
    $key_549b = { 07 f4 [2] 23 fa [2] 08 d6 [2] 26 f4 [2] 32 ef [2] 3d f5 [2] 23 e8 [2] 21 e9 [2] 3a ef [2] 26 e8 [2] 3a c7 }

  condition:
    any of them
}