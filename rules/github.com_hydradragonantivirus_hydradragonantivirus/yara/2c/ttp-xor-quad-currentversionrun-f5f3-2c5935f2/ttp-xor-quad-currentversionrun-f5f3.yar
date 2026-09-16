rule TTP_XOR_QUAD_CurrentVersionRun_f5f3 {
  strings:
    $key_f5f3 = { a6 9c [2] 82 92 [2] a9 be [2] 87 9c [2] 93 87 [2] 9c 9d [2] 82 80 [2] 80 81 [2] 9b 87 [2] 87 80 [2] 9b af }

  condition:
    any of them
}