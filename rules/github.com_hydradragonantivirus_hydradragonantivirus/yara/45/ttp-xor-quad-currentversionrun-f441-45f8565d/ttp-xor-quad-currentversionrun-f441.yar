rule TTP_XOR_QUAD_CurrentVersionRun_f441 {
  strings:
    $key_f441 = { a7 2e [2] 83 20 [2] a8 0c [2] 86 2e [2] 92 35 [2] 9d 2f [2] 83 32 [2] 81 33 [2] 9a 35 [2] 86 32 [2] 9a 1d }

  condition:
    any of them
}