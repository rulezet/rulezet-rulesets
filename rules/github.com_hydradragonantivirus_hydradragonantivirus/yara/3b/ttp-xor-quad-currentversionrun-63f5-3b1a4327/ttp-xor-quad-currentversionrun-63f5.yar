rule TTP_XOR_QUAD_CurrentVersionRun_63f5 {
  strings:
    $key_63f5 = { 30 9a [2] 14 94 [2] 3f b8 [2] 11 9a [2] 05 81 [2] 0a 9b [2] 14 86 [2] 16 87 [2] 0d 81 [2] 11 86 [2] 0d a9 }

  condition:
    any of them
}