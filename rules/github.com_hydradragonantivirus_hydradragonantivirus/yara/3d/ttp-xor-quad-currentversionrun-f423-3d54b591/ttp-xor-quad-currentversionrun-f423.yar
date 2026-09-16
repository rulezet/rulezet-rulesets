rule TTP_XOR_QUAD_CurrentVersionRun_f423 {
  strings:
    $key_f423 = { a7 4c [2] 83 42 [2] a8 6e [2] 86 4c [2] 92 57 [2] 9d 4d [2] 83 50 [2] 81 51 [2] 9a 57 [2] 86 50 [2] 9a 7f }

  condition:
    any of them
}