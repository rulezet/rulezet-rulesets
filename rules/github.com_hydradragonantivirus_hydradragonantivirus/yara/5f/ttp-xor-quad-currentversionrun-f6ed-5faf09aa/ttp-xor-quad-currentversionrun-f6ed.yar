rule TTP_XOR_QUAD_CurrentVersionRun_f6ed {
  strings:
    $key_f6ed = { a5 82 [2] 81 8c [2] aa a0 [2] 84 82 [2] 90 99 [2] 9f 83 [2] 81 9e [2] 83 9f [2] 98 99 [2] 84 9e [2] 98 b1 }

  condition:
    any of them
}