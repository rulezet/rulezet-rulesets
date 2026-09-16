rule TTP_XOR_QUAD_CurrentVersionRun_f5ed {
  strings:
    $key_f5ed = { a6 82 [2] 82 8c [2] a9 a0 [2] 87 82 [2] 93 99 [2] 9c 83 [2] 82 9e [2] 80 9f [2] 9b 99 [2] 87 9e [2] 9b b1 }

  condition:
    any of them
}