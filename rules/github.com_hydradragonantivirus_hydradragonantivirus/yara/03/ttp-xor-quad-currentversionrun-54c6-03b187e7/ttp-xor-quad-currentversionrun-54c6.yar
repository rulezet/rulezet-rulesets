rule TTP_XOR_QUAD_CurrentVersionRun_54c6 {
  strings:
    $key_54c6 = { 07 a9 [2] 23 a7 [2] 08 8b [2] 26 a9 [2] 32 b2 [2] 3d a8 [2] 23 b5 [2] 21 b4 [2] 3a b2 [2] 26 b5 [2] 3a 9a }

  condition:
    any of them
}