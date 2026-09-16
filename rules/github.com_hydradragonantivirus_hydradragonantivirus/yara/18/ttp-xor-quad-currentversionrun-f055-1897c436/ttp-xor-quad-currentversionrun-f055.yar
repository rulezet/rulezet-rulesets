rule TTP_XOR_QUAD_CurrentVersionRun_f055 {
  strings:
    $key_f055 = { a3 3a [2] 87 34 [2] ac 18 [2] 82 3a [2] 96 21 [2] 99 3b [2] 87 26 [2] 85 27 [2] 9e 21 [2] 82 26 [2] 9e 09 }

  condition:
    any of them
}