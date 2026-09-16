rule TTP_XOR_QUAD_CurrentVersionRun_f447 {
  strings:
    $key_f447 = { a7 28 [2] 83 26 [2] a8 0a [2] 86 28 [2] 92 33 [2] 9d 29 [2] 83 34 [2] 81 35 [2] 9a 33 [2] 86 34 [2] 9a 1b }

  condition:
    any of them
}