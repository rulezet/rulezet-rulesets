rule TTP_XOR_QUAD_CurrentVersionRun_f0f4 {
  strings:
    $key_f0f4 = { a3 9b [2] 87 95 [2] ac b9 [2] 82 9b [2] 96 80 [2] 99 9a [2] 87 87 [2] 85 86 [2] 9e 80 [2] 82 87 [2] 9e a8 }

  condition:
    any of them
}