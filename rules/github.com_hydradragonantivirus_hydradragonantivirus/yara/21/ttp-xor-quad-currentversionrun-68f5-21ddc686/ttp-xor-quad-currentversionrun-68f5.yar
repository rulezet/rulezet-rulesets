rule TTP_XOR_QUAD_CurrentVersionRun_68f5 {
  strings:
    $key_68f5 = { 3b 9a [2] 1f 94 [2] 34 b8 [2] 1a 9a [2] 0e 81 [2] 01 9b [2] 1f 86 [2] 1d 87 [2] 06 81 [2] 1a 86 [2] 06 a9 }

  condition:
    any of them
}