rule TTP_XOR_QUAD_CurrentVersionRun_f431 {
  strings:
    $key_f431 = { a7 5e [2] 83 50 [2] a8 7c [2] 86 5e [2] 92 45 [2] 9d 5f [2] 83 42 [2] 81 43 [2] 9a 45 [2] 86 42 [2] 9a 6d }

  condition:
    any of them
}