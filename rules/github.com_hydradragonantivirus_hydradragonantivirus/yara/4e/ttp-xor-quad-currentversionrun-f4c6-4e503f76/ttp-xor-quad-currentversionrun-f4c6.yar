rule TTP_XOR_QUAD_CurrentVersionRun_f4c6 {
  strings:
    $key_f4c6 = { a7 a9 [2] 83 a7 [2] a8 8b [2] 86 a9 [2] 92 b2 [2] 9d a8 [2] 83 b5 [2] 81 b4 [2] 9a b2 [2] 86 b5 [2] 9a 9a }

  condition:
    any of them
}