rule TTP_XOR_QUAD_CurrentVersionRun_f3f4 {
  strings:
    $key_f3f4 = { a0 9b [2] 84 95 [2] af b9 [2] 81 9b [2] 95 80 [2] 9a 9a [2] 84 87 [2] 86 86 [2] 9d 80 [2] 81 87 [2] 9d a8 }

  condition:
    any of them
}