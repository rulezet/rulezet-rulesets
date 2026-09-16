rule TTP_XOR_QUAD_CurrentVersionRun_f068 {
  strings:
    $key_f068 = { a3 07 [2] 87 09 [2] ac 25 [2] 82 07 [2] 96 1c [2] 99 06 [2] 87 1b [2] 85 1a [2] 9e 1c [2] 82 1b [2] 9e 34 }

  condition:
    any of them
}