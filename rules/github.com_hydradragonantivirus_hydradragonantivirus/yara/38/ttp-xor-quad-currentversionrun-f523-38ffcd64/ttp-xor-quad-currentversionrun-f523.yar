rule TTP_XOR_QUAD_CurrentVersionRun_f523 {
  strings:
    $key_f523 = { a6 4c [2] 82 42 [2] a9 6e [2] 87 4c [2] 93 57 [2] 9c 4d [2] 82 50 [2] 80 51 [2] 9b 57 [2] 87 50 [2] 9b 7f }

  condition:
    any of them
}