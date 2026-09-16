rule TTP_XOR_QUAD_CurrentVersionRun_77f5 {
  strings:
    $key_77f5 = { 24 9a [2] 00 94 [2] 2b b8 [2] 05 9a [2] 11 81 [2] 1e 9b [2] 00 86 [2] 02 87 [2] 19 81 [2] 05 86 [2] 19 a9 }

  condition:
    any of them
}