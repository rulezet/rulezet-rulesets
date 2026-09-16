rule TTP_XOR_QUAD_CurrentVersionRun_f406 {
  strings:
    $key_f406 = { a7 69 [2] 83 67 [2] a8 4b [2] 86 69 [2] 92 72 [2] 9d 68 [2] 83 75 [2] 81 74 [2] 9a 72 [2] 86 75 [2] 9a 5a }

  condition:
    any of them
}