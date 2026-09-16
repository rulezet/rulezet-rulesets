rule TTP_XOR_QUAD_CurrentVersionRun_f531 {
  strings:
    $key_f531 = { a6 5e [2] 82 50 [2] a9 7c [2] 87 5e [2] 93 45 [2] 9c 5f [2] 82 42 [2] 80 43 [2] 9b 45 [2] 87 42 [2] 9b 6d }

  condition:
    any of them
}