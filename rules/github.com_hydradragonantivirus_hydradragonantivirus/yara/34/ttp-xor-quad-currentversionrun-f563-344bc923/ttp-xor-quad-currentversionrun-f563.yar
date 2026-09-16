rule TTP_XOR_QUAD_CurrentVersionRun_f563 {
  strings:
    $key_f563 = { a6 0c [2] 82 02 [2] a9 2e [2] 87 0c [2] 93 17 [2] 9c 0d [2] 82 10 [2] 80 11 [2] 9b 17 [2] 87 10 [2] 9b 3f }

  condition:
    any of them
}