rule TTP_XOR_QUAD_CurrentVersionRun_faf5 {
  strings:
    $key_faf5 = { a9 9a [2] 8d 94 [2] a6 b8 [2] 88 9a [2] 9c 81 [2] 93 9b [2] 8d 86 [2] 8f 87 [2] 94 81 [2] 88 86 [2] 94 a9 }

  condition:
    any of them
}