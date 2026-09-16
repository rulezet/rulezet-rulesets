rule TTP_XOR_QUAD_CurrentVersionRun_f1f4 {
  strings:
    $key_f1f4 = { a2 9b [2] 86 95 [2] ad b9 [2] 83 9b [2] 97 80 [2] 98 9a [2] 86 87 [2] 84 86 [2] 9f 80 [2] 83 87 [2] 9f a8 }

  condition:
    any of them
}