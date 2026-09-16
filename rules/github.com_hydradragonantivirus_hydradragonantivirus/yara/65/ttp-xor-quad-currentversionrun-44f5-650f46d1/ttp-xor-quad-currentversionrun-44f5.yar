rule TTP_XOR_QUAD_CurrentVersionRun_44f5 {
  strings:
    $key_44f5 = { 17 9a [2] 33 94 [2] 18 b8 [2] 36 9a [2] 22 81 [2] 2d 9b [2] 33 86 [2] 31 87 [2] 2a 81 [2] 36 86 [2] 2a a9 }

  condition:
    any of them
}