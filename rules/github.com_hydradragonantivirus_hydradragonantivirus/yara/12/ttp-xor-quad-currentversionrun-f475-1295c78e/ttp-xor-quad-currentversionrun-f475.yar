rule TTP_XOR_QUAD_CurrentVersionRun_f475 {
  strings:
    $key_f475 = { a7 1a [2] 83 14 [2] a8 38 [2] 86 1a [2] 92 01 [2] 9d 1b [2] 83 06 [2] 81 07 [2] 9a 01 [2] 86 06 [2] 9a 29 }

  condition:
    any of them
}