rule TTP_XOR_QUAD_CurrentVersionRun_04f5 {
  strings:
    $key_04f5 = { 57 9a [2] 73 94 [2] 58 b8 [2] 76 9a [2] 62 81 [2] 6d 9b [2] 73 86 [2] 71 87 [2] 6a 81 [2] 76 86 [2] 6a a9 }

  condition:
    any of them
}