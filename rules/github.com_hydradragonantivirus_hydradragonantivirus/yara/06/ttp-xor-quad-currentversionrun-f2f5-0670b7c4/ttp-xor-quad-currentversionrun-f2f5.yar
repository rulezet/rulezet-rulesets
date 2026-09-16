rule TTP_XOR_QUAD_CurrentVersionRun_f2f5 {
  strings:
    $key_f2f5 = { a1 9a [2] 85 94 [2] ae b8 [2] 80 9a [2] 94 81 [2] 9b 9b [2] 85 86 [2] 87 87 [2] 9c 81 [2] 80 86 [2] 9c a9 }

  condition:
    any of them
}