rule TTP_XOR_QUAD_CurrentVersionRun_f059 {
  strings:
    $key_f059 = { a3 36 [2] 87 38 [2] ac 14 [2] 82 36 [2] 96 2d [2] 99 37 [2] 87 2a [2] 85 2b [2] 9e 2d [2] 82 2a [2] 9e 05 }

  condition:
    any of them
}