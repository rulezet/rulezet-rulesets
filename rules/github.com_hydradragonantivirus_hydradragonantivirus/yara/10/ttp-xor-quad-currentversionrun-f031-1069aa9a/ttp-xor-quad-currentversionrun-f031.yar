rule TTP_XOR_QUAD_CurrentVersionRun_f031 {
  strings:
    $key_f031 = { a3 5e [2] 87 50 [2] ac 7c [2] 82 5e [2] 96 45 [2] 99 5f [2] 87 42 [2] 85 43 [2] 9e 45 [2] 82 42 [2] 9e 6d }

  condition:
    any of them
}