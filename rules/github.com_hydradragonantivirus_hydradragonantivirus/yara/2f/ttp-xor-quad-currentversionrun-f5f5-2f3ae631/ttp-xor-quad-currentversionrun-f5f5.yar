rule TTP_XOR_QUAD_CurrentVersionRun_f5f5 {
  strings:
    $key_f5f5 = { a6 9a [2] 82 94 [2] a9 b8 [2] 87 9a [2] 93 81 [2] 9c 9b [2] 82 86 [2] 80 87 [2] 9b 81 [2] 87 86 [2] 9b a9 }

  condition:
    any of them
}