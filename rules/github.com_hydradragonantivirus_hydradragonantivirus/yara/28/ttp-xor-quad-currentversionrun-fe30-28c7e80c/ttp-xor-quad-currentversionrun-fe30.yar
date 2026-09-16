rule TTP_XOR_QUAD_CurrentVersionRun_fe30 {
  strings:
    $key_fe30 = { ad 5f [2] 89 51 [2] a2 7d [2] 8c 5f [2] 98 44 [2] 97 5e [2] 89 43 [2] 8b 42 [2] 90 44 [2] 8c 43 [2] 90 6c }

  condition:
    any of them
}