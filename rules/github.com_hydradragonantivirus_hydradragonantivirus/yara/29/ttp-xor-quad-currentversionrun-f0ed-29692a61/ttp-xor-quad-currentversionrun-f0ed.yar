rule TTP_XOR_QUAD_CurrentVersionRun_f0ed {
  strings:
    $key_f0ed = { a3 82 [2] 87 8c [2] ac a0 [2] 82 82 [2] 96 99 [2] 99 83 [2] 87 9e [2] 85 9f [2] 9e 99 [2] 82 9e [2] 9e b1 }

  condition:
    any of them
}