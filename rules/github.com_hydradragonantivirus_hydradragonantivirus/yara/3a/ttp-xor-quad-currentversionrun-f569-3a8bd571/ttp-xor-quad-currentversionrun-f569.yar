rule TTP_XOR_QUAD_CurrentVersionRun_f569 {
  strings:
    $key_f569 = { a6 06 [2] 82 08 [2] a9 24 [2] 87 06 [2] 93 1d [2] 9c 07 [2] 82 1a [2] 80 1b [2] 9b 1d [2] 87 1a [2] 9b 35 }

  condition:
    any of them
}