rule TTP_XOR_QUAD_CurrentVersionRun_f7f4 {
  strings:
    $key_f7f4 = { a4 9b [2] 80 95 [2] ab b9 [2] 85 9b [2] 91 80 [2] 9e 9a [2] 80 87 [2] 82 86 [2] 99 80 [2] 85 87 [2] 99 a8 }

  condition:
    any of them
}