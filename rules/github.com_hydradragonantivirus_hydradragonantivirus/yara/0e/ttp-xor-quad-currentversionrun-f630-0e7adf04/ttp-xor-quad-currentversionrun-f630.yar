rule TTP_XOR_QUAD_CurrentVersionRun_f630 {
  strings:
    $key_f630 = { a5 5f [2] 81 51 [2] aa 7d [2] 84 5f [2] 90 44 [2] 9f 5e [2] 81 43 [2] 83 42 [2] 98 44 [2] 84 43 [2] 98 6c }

  condition:
    any of them
}