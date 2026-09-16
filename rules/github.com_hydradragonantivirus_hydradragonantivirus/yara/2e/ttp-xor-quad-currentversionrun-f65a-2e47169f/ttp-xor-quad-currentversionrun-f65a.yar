rule TTP_XOR_QUAD_CurrentVersionRun_f65a {
  strings:
    $key_f65a = { a5 35 [2] 81 3b [2] aa 17 [2] 84 35 [2] 90 2e [2] 9f 34 [2] 81 29 [2] 83 28 [2] 98 2e [2] 84 29 [2] 98 06 }

  condition:
    any of them
}