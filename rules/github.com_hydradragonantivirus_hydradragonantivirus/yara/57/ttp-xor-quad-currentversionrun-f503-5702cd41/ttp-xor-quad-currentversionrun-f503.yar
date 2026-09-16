rule TTP_XOR_QUAD_CurrentVersionRun_f503 {
  strings:
    $key_f503 = { a6 6c [2] 82 62 [2] a9 4e [2] 87 6c [2] 93 77 [2] 9c 6d [2] 82 70 [2] 80 71 [2] 9b 77 [2] 87 70 [2] 9b 5f }

  condition:
    any of them
}