rule TTP_XOR_QUAD_CurrentVersionRun_f467 {
  strings:
    $key_f467 = { a7 08 [2] 83 06 [2] a8 2a [2] 86 08 [2] 92 13 [2] 9d 09 [2] 83 14 [2] 81 15 [2] 9a 13 [2] 86 14 [2] 9a 3b }

  condition:
    any of them
}