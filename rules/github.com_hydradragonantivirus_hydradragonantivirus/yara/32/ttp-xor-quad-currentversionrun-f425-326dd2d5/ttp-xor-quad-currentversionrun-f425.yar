rule TTP_XOR_QUAD_CurrentVersionRun_f425 {
  strings:
    $key_f425 = { a7 4a [2] 83 44 [2] a8 68 [2] 86 4a [2] 92 51 [2] 9d 4b [2] 83 56 [2] 81 57 [2] 9a 51 [2] 86 56 [2] 9a 79 }

  condition:
    any of them
}