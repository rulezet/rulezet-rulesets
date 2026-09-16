rule TTP_XOR_QUAD_CurrentVersionRun_54d6 {
  strings:
    $key_54d6 = { 07 b9 [2] 23 b7 [2] 08 9b [2] 26 b9 [2] 32 a2 [2] 3d b8 [2] 23 a5 [2] 21 a4 [2] 3a a2 [2] 26 a5 [2] 3a 8a }

  condition:
    any of them
}