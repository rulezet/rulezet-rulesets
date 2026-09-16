rule TTP_XOR_QUAD_CurrentVersionRun_f450 {
  strings:
    $key_f450 = { a7 3f [2] 83 31 [2] a8 1d [2] 86 3f [2] 92 24 [2] 9d 3e [2] 83 23 [2] 81 22 [2] 9a 24 [2] 86 23 [2] 9a 0c }

  condition:
    any of them
}