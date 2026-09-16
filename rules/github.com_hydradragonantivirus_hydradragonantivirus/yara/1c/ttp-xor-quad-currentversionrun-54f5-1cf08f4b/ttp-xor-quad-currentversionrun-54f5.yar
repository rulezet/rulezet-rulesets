rule TTP_XOR_QUAD_CurrentVersionRun_54f5 {
  strings:
    $key_54f5 = { 07 9a [2] 23 94 [2] 08 b8 [2] 26 9a [2] 32 81 [2] 3d 9b [2] 23 86 [2] 21 87 [2] 3a 81 [2] 26 86 [2] 3a a9 }

  condition:
    any of them
}