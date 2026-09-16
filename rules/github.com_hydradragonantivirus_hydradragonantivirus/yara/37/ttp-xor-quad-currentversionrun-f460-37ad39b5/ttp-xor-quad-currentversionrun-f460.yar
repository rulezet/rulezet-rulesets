rule TTP_XOR_QUAD_CurrentVersionRun_f460 {
  strings:
    $key_f460 = { a7 0f [2] 83 01 [2] a8 2d [2] 86 0f [2] 92 14 [2] 9d 0e [2] 83 13 [2] 81 12 [2] 9a 14 [2] 86 13 [2] 9a 3c }

  condition:
    any of them
}