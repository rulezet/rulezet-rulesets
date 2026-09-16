rule TTP_XOR_QUAD_CurrentVersionRun_f477 {
  strings:
    $key_f477 = { a7 18 [2] 83 16 [2] a8 3a [2] 86 18 [2] 92 03 [2] 9d 19 [2] 83 04 [2] 81 05 [2] 9a 03 [2] 86 04 [2] 9a 2b }

  condition:
    any of them
}