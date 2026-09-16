rule TTP_XOR_QUAD_CurrentVersionRun_f4e8 {
  strings:
    $key_f4e8 = { a7 87 [2] 83 89 [2] a8 a5 [2] 86 87 [2] 92 9c [2] 9d 86 [2] 83 9b [2] 81 9a [2] 9a 9c [2] 86 9b [2] 9a b4 }

  condition:
    any of them
}