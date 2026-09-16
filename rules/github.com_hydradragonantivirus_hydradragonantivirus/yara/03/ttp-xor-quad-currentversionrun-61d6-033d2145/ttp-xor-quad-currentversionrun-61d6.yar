rule TTP_XOR_QUAD_CurrentVersionRun_61d6 {
  strings:
    $key_61d6 = { 32 b9 [2] 16 b7 [2] 3d 9b [2] 13 b9 [2] 07 a2 [2] 08 b8 [2] 16 a5 [2] 14 a4 [2] 0f a2 [2] 13 a5 [2] 0f 8a }

  condition:
    any of them
}