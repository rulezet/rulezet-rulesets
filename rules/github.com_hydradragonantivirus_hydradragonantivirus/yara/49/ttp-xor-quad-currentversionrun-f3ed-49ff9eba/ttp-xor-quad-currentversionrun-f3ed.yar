rule TTP_XOR_QUAD_CurrentVersionRun_f3ed {
  strings:
    $key_f3ed = { a0 82 [2] 84 8c [2] af a0 [2] 81 82 [2] 95 99 [2] 9a 83 [2] 84 9e [2] 86 9f [2] 9d 99 [2] 81 9e [2] 9d b1 }

  condition:
    any of them
}