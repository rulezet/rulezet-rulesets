rule TTP_XOR_QUAD_CurrentVersionRun_78f5 {
  strings:
    $key_78f5 = { 2b 9a [2] 0f 94 [2] 24 b8 [2] 0a 9a [2] 1e 81 [2] 11 9b [2] 0f 86 [2] 0d 87 [2] 16 81 [2] 0a 86 [2] 16 a9 }

  condition:
    any of them
}