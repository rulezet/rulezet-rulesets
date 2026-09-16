rule TTP_XOR_QUAD_CurrentVersionRun_57f5 {
  strings:
    $key_57f5 = { 04 9a [2] 20 94 [2] 0b b8 [2] 25 9a [2] 31 81 [2] 3e 9b [2] 20 86 [2] 22 87 [2] 39 81 [2] 25 86 [2] 39 a9 }

  condition:
    any of them
}