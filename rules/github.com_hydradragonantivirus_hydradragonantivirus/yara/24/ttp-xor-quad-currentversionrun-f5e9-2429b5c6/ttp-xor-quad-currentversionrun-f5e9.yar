rule TTP_XOR_QUAD_CurrentVersionRun_f5e9 {
  strings:
    $key_f5e9 = { a6 86 [2] 82 88 [2] a9 a4 [2] 87 86 [2] 93 9d [2] 9c 87 [2] 82 9a [2] 80 9b [2] 9b 9d [2] 87 9a [2] 9b b5 }

  condition:
    any of them
}