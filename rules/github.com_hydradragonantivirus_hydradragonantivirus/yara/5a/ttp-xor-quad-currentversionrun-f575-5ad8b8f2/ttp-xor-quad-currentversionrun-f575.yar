rule TTP_XOR_QUAD_CurrentVersionRun_f575 {
  strings:
    $key_f575 = { a6 1a [2] 82 14 [2] a9 38 [2] 87 1a [2] 93 01 [2] 9c 1b [2] 82 06 [2] 80 07 [2] 9b 01 [2] 87 06 [2] 9b 29 }

  condition:
    any of them
}