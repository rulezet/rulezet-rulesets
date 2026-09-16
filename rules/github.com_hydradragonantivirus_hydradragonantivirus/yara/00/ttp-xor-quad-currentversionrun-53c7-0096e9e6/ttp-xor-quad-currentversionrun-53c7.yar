rule TTP_XOR_QUAD_CurrentVersionRun_53c7 {
  strings:
    $key_53c7 = { 00 a8 [2] 24 a6 [2] 0f 8a [2] 21 a8 [2] 35 b3 [2] 3a a9 [2] 24 b4 [2] 26 b5 [2] 3d b3 [2] 21 b4 [2] 3d 9b }

  condition:
    any of them
}