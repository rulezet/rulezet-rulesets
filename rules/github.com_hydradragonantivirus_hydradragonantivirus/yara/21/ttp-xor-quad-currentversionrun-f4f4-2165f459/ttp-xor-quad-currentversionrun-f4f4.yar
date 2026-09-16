rule TTP_XOR_QUAD_CurrentVersionRun_f4f4 {
  strings:
    $key_f4f4 = { a7 9b [2] 83 95 [2] a8 b9 [2] 86 9b [2] 92 80 [2] 9d 9a [2] 83 87 [2] 81 86 [2] 9a 80 [2] 86 87 [2] 9a a8 }

  condition:
    any of them
}