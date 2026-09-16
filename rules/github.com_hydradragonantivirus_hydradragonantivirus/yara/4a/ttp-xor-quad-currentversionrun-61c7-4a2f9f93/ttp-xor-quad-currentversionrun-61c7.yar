rule TTP_XOR_QUAD_CurrentVersionRun_61c7 {
  strings:
    $key_61c7 = { 32 a8 [2] 16 a6 [2] 3d 8a [2] 13 a8 [2] 07 b3 [2] 08 a9 [2] 16 b4 [2] 14 b5 [2] 0f b3 [2] 13 b4 [2] 0f 9b }

  condition:
    any of them
}