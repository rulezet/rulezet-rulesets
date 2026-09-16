rule TTP_XOR_QUAD_CurrentVersionRun_f045 {
  strings:
    $key_f045 = { a3 2a [2] 87 24 [2] ac 08 [2] 82 2a [2] 96 31 [2] 99 2b [2] 87 36 [2] 85 37 [2] 9e 31 [2] 82 36 [2] 9e 19 }

  condition:
    any of them
}