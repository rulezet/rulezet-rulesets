rule TTP_XOR_QUAD_CurrentVersionRun_f457 {
  strings:
    $key_f457 = { a7 38 [2] 83 36 [2] a8 1a [2] 86 38 [2] 92 23 [2] 9d 39 [2] 83 24 [2] 81 25 [2] 9a 23 [2] 86 24 [2] 9a 0b }

  condition:
    any of them
}