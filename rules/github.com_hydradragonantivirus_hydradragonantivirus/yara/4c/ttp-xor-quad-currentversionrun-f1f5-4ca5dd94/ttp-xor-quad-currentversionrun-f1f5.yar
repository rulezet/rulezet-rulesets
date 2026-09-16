rule TTP_XOR_QUAD_CurrentVersionRun_f1f5 {
  strings:
    $key_f1f5 = { a2 9a [2] 86 94 [2] ad b8 [2] 83 9a [2] 97 81 [2] 98 9b [2] 86 86 [2] 84 87 [2] 9f 81 [2] 83 86 [2] 9f a9 }

  condition:
    any of them
}