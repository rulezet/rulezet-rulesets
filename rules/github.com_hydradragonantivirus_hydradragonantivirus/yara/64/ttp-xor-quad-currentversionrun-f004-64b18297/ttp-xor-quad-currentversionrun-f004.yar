rule TTP_XOR_QUAD_CurrentVersionRun_f004 {
  strings:
    $key_f004 = { a3 6b [2] 87 65 [2] ac 49 [2] 82 6b [2] 96 70 [2] 99 6a [2] 87 77 [2] 85 76 [2] 9e 70 [2] 82 77 [2] 9e 58 }

  condition:
    any of them
}