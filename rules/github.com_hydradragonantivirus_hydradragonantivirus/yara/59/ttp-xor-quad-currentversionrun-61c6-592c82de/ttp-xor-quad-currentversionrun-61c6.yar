rule TTP_XOR_QUAD_CurrentVersionRun_61c6 {
  strings:
    $key_61c6 = { 32 a9 [2] 16 a7 [2] 3d 8b [2] 13 a9 [2] 07 b2 [2] 08 a8 [2] 16 b5 [2] 14 b4 [2] 0f b2 [2] 13 b5 [2] 0f 9a }

  condition:
    any of them
}