rule TTP_XOR_QUAD_CurrentVersionRun_f631 {
  strings:
    $key_f631 = { a5 5e [2] 81 50 [2] aa 7c [2] 84 5e [2] 90 45 [2] 9f 5f [2] 81 42 [2] 83 43 [2] 98 45 [2] 84 42 [2] 98 6d }

  condition:
    any of them
}