rule TTP_XOR_QUAD_CurrentVersionRun_54f4 {
  strings:
    $key_54f4 = { 07 9b [2] 23 95 [2] 08 b9 [2] 26 9b [2] 32 80 [2] 3d 9a [2] 23 87 [2] 21 86 [2] 3a 80 [2] 26 87 [2] 3a a8 }

  condition:
    any of them
}