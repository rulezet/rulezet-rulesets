rule TTP_XOR_QUAD_CurrentVersionRun_53c6 {
  strings:
    $key_53c6 = { 00 a9 [2] 24 a7 [2] 0f 8b [2] 21 a9 [2] 35 b2 [2] 3a a8 [2] 24 b5 [2] 26 b4 [2] 3d b2 [2] 21 b5 [2] 3d 9a }

  condition:
    any of them
}