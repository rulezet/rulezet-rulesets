rule TTP_XOR_QUAD_CurrentVersionRun_f4c7 {
  strings:
    $key_f4c7 = { a7 a8 [2] 83 a6 [2] a8 8a [2] 86 a8 [2] 92 b3 [2] 9d a9 [2] 83 b4 [2] 81 b5 [2] 9a b3 [2] 86 b4 [2] 9a 9b }

  condition:
    any of them
}