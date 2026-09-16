rule TTP_XOR_QUAD_CurrentVersionRun_64f5 {
  strings:
    $key_64f5 = { 37 9a [2] 13 94 [2] 38 b8 [2] 16 9a [2] 02 81 [2] 0d 9b [2] 13 86 [2] 11 87 [2] 0a 81 [2] 16 86 [2] 0a a9 }

  condition:
    any of them
}