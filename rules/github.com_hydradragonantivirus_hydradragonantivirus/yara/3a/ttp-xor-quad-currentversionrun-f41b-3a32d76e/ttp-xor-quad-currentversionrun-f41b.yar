rule TTP_XOR_QUAD_CurrentVersionRun_f41b {
  strings:
    $key_f41b = { a7 74 [2] 83 7a [2] a8 56 [2] 86 74 [2] 92 6f [2] 9d 75 [2] 83 68 [2] 81 69 [2] 9a 6f [2] 86 68 [2] 9a 47 }

  condition:
    any of them
}